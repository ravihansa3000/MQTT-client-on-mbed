#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include "mbed.h"
#include "mbed_events.h"
#include "rtos.h"

#include <string.h>
#include <cstdio>
#include <map>
#include <memory>
#include "EthernetInterface.h"
#include "MQTTPacket.h"
#include "RtosLogger.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

#if defined(MQTT_CLIENT_DEBUG_ENABLED) && MQTT_CLIENT_DEBUG_ENABLED == 1
#define DEBUG_LEVEL 1
#include "mbedtls/debug.h"
#endif

#undef DBG
#undef INFO
#undef WARN
#undef ERR
#if defined(MQTT_CLIENT_DEBUG_ENABLED) && MQTT_CLIENT_DEBUG_ENABLED == 1
#define DBG(x, ...) _logger->atprintf("[DEBUG][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#else
#define DBG(x, ...)
#endif

#define INFO(x, ...) _logger->atprintf("[INFO][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#define WARN(x, ...) _logger->atprintf("[WARN][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#define ERR(x, ...) _logger->atprintf("[ERROR][MQTTClient] " x "\r\n", ##__VA_ARGS__);

/** EVENTS_LOG_EVENT_SIZE
 *  Minimum size of a log event
 *  This size fits a Callback<void(int)> at minimum
 */
#define EVENTS_MQTT_PUBLISH_EVENT_SIZE (EQUEUE_EVENT_SIZE - 2 * sizeof(void *) + sizeof(int))

#define MQTT_COMMAND_TIMEOUT 5000  // MQTT network command timeout in millis
#define MQTT_SOCKET_TIMEOUT 5000   // Network socket timeout in millis
#define MAX_MQTT_PACKET_SIZE 1200
#define MAX_MQTT_PAYLOAD_SIZE 1000
#define MAX_MQTT_TOPIC_SIZE 100
#define MAX_MQTT_MESSAGE_HANDLERS 32
#define MAX_MQTT_PUBLISH_MESSAGES 8
#define MQTT_PUBLISH_EVENT_QUEUE_SIZE 32
#define MQTT_CRT_BUFFER_SIZE 4096
#define MQTT_PUBLISH_TIMEOUT 10000  // MQTT publish message timeout in millis

namespace MQTT {

enum QoS { QOS0, QOS1, QOS2 };

enum CONNACK_RC {
  ACCEPTED = 0,
  UNACCEPTABLE_PROTOCOL_VER,
  IDENTIFIER_REJECTED,
  SERVER_UNAVAILABLE,
  BAD_CREDENTIALS,
  NOT_AUTHORIZED
};

enum RC {
  SUCCESS = 0,
  FAILURE = -1,
  INVALID = -2,
  TIMEOUT = -3,
  BUFFER_OVERFLOW = -4,
  MQTT_ERROR = -5,
  NETWORK_ERROR = -6,
  BUFFER_FULL = -7
};  // return codes

struct MQTTMessage {
  MQTTMessage() : id(0), qos(QOS0), retained(false), dup(false), payloadlen(0), topic{0}, payload{0} {}

  MQTTMessage(unsigned short _id, QoS _qos, bool _retained, bool _dup, size_t _payloadlen, const char *_topic,
              const char *_payload)
      : id(_id), qos(_qos), retained(_retained), dup(_dup), payloadlen(_payloadlen) {
    snprintf(topic, sizeof(MQTTMessage::topic), "%s", _topic);
    snprintf(payload, sizeof(MQTTMessage::payload), "%s", _payload);
  }

  unsigned short id;
  QoS qos;
  bool retained;
  bool dup;
  size_t payloadlen;
  char topic[MAX_MQTT_TOPIC_SIZE + 1];
  char payload[MAX_MQTT_PAYLOAD_SIZE + 1];
};

class PacketId {
 public:
  PacketId() : _next(0) {}

  unsigned short get_next() volatile {
    _next++;
    _next = (_next > MAX_PACKET_ID) ? 1 : _next;
    return (unsigned short)_next;
  }

 private:
  static const int MAX_PACKET_ID = 65535;
  volatile int _next;
};

class MQTTClient {
 public:
  enum MQTTClientError { Ok = 0, InvalidArgsError = -1002 };

  MQTTClient(RtosLogger *logger, NetworkInterface *net, bool use_tls = true, bool ssl_cert_verify = true,
             const char *pem = DEFAULT_SSL_CA_PEM);

  ~MQTTClient();

  /**
   *  Sets the connection parameters. Must be called before running the start_listener as a thread.
   *
   *  @param host - pointer to the host where the MQTT broker running
   *  @param port - the port number to connect, 1883 for non secure connections, 8883 for
   *                secure connections
   *  @param options - the connect data used for logging into the MQTT broker.
   */
  void set_connection_parameters(const char *host, uint16_t port, MQTTPacket_connectData &options);

  int publish(const char *topic, const char *payload, MQTT::QoS qos = MQTT::QoS::QOS0, bool retained = false,
              bool dup = false);

  int post_publish(const char *topic, const char *payload, MQTT::QoS qos = MQTT::QoS::QOS0, bool retained = false,
                   bool dup = false);

  int set_message_handler(const char *topic, Callback<void(MQTTMessage &)> cb);

  // TODO: Add unsubscribe functionality.

  int cycle();

  bool is_connected();

  int disconnect();

  void clear_send_buffer();

  EventQueue &equeue();

 protected:
  // SSL/TLS variables
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_x509_crt _cacert;
  mbedtls_x509_crt _owncert;
  mbedtls_pk_context _pkctx;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _ssl_conf;
  mbedtls_ssl_session _ssl_saved_session;

  /*
   * List of trusted root CA certificates
   * TODO: Move this certificate data onto the SD card.
   */
  static char DEFAULT_SSL_CA_PEM[];

  static char SSL_OWN_CERT_PEM[];
  static char SSL_OWN_KEY_PEM[];

  static const char *DRBG_PERS;
  int handle_publish_message();
  int connect();

  static int ssl_recv(void *ctx, unsigned char *buf, size_t len);
  static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

 private:
  volatile bool _is_connected;
  volatile bool _ssl_initialized;
  volatile bool _has_saved_session;
  volatile bool _ping_request_sent;
  RtosLogger *_logger;
  NetworkInterface *_network;
  EventQueue _equeue;
  bool _use_tls;
  bool _ssl_cert_verify;
  const char *_ssl_ca_pem;
  volatile PacketId _packetid;
  string _host;
  uint16_t _port;
  MQTTPacket_connectData _connect_options;
  unsigned char _sendbuf[MAX_MQTT_PACKET_SIZE];
  unsigned char _readbuf[MAX_MQTT_PACKET_SIZE];
  unsigned short _keepalive_interval;
  TCPSocket _tcpsocket;
  Mutex _lock;
  Timer _timer;

  struct MessageHandlers {
    const char *topic_filter;
    Callback<void(MQTTMessage &)> topic_cb;
  } _message_handlers[MAX_MQTT_MESSAGE_HANDLERS];  // Message handlers are indexed by subscription topic

  struct PublishBuffer {
    PublishBuffer() : pub_message{} {}

    PublishBuffer(MQTTMessage _pub_message) : pub_message{_pub_message} {}

    MQTTMessage pub_message;
    Timer pub_timer;
  } _publishbuf[MAX_MQTT_PUBLISH_MESSAGES];

#if MQTTCLIENT_QOS1 || MQTTCLIENT_QOS2
  unsigned char _last_published[MAX_MQTT_PACKET_SIZE];  // store the last publish for sending on reconnect
  int _inflight_len;
  unsigned short _inflight_msgid;
  enum QoS _inflight_qos;
#endif

#if MQTTCLIENT_QOS2
  bool _pubrel;
#if !defined(MAX_INCOMING_QOS2_MESSAGES)
#define MAX_INCOMING_QOS2_MESSAGES 32
#endif
  unsigned short _qos2_messages[MAX_INCOMING_QOS2_MESSAGES];
  bool is_qos2_msgid_free(unsigned short id);
  bool use_qos_msgid(unsigned short id);
  void free_qos2_msgid(unsigned short id);
#endif

  int has_connection_timed_out();
  int login();
  int init_tls();
  void free_tls();
  int do_tls_handshake();
  int process_subscriptions();
  int read_packet();
  int send_packet(size_t length);
  int read_packet_length(int *value);
  int read_until(int packet_type, int timeout);
  int read_bytes_to_buffer(char *buffer, size_t size);
  int send_bytes_from_buffer(char *buffer, size_t size);
  bool is_topic_matched(char *filter, MQTTString &mqtt_topic);
  void post_publish_callback(int index);
  void reset_connection_timer();
  void send_ping_request();
  void clean_session();
  void mqtt_health_check();
};
}  // namespace MQTT
#endif
