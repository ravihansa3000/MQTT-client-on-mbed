#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include "EthernetInterface.h"
#include "mbed.h"
#include "mbed_events.h"
#include "rtos.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

#if defined(MQTT_CLIENT_DEBUG_ENABLED) && MQTT_CLIENT_DEBUG_ENABLED == 1
#define DEBUG_LEVEL 1
#include "mbedtls/debug.h"
#endif

#include <cstdio>
#include <map>
#include <string>
#include "MQTTPacket.h"
#include "RtosLogger.h"

#undef DBG
#undef INFO
#undef WARN
#undef ERR
#if MQTT_CLIENT_DEBUG_ENABLED == 1
#define DBG(x, ...) _logger->printf_time("[DEBUG][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#else
#define DBG(x, ...)
#endif

#define INFO(x, ...) _logger->printf_time("[INFO][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#define WARN(x, ...) _logger->printf_time("[WARN][MQTTClient] " x "\r\n", ##__VA_ARGS__);
#define ERR(x, ...) _logger->printf_time("[ERROR][MQTTClient] " x "\r\n", ##__VA_ARGS__);

#define COMMAND_TIMEOUT 5000
#define DEFAULT_SOCKET_TIMEOUT 5000
#define MAX_MQTT_PACKET_SIZE 1200
#define MAX_MQTT_PAYLOAD_SIZE 1024
#define MQTT_RECONNECT_TIMEOUT 5000
#define MQTT_EVENT_QUEUE_SIZE 128
#define PUBLISHER_STACK_SIZE 2048
#define MQTT_HEALTH_CHECK_INTERVAL 30.0f  // 30 seconds

namespace MQTT {

typedef enum { QOS0, QOS1, QOS2 } QoS;

typedef enum { BUFFER_OVERFLOW = -3, TIMEOUT = -2, FAILURE = -1, SUCCESS = 0 } return_code;

typedef struct {
  QoS qos;
  bool retained;
  bool dup;
  unsigned short id;
  void *payload;
  size_t payloadlen;
} Message;

// TODO:
// Merge this struct with the one above, in order to use the same
// data structure for sending and receiving. I need to simplify
// the PubMessage to not contain pointers like the one above.
typedef struct {
  char topic[100];
  QoS qos;
  unsigned short id;
  size_t payloadlen;
  char payload[MAX_MQTT_PAYLOAD_SIZE];
} PubMessage, *pPubMessage;

struct MessageData {
  MessageData(MQTTString &_topic, Message &_message) : message(_message), topic(_topic) {}

  Message &message;
  MQTTString &topic;
};

class PacketId {
 public:
  PacketId() : _next(0) {}

  int get_next() volatile {
    _next++;
    _next = (_next > MAX_PACKET_ID) ? 1 : _next;
    return _next;
  }

 private:
  static const int MAX_PACKET_ID = 65535;
  volatile int _next;
};

class MQTTClient {
 public:
  enum MQTTClientError { Ok = 0, TCPSocketError = -1001, PublisherError = -1002 };

  MQTTClient(RtosLogger *logger, NetworkInterface *net, bool use_tls = true, bool ssl_cert_verify = true,
             const char *pem = DEFAULT_SSL_CA_PEM);

  ~MQTTClient();

  int init();

  /**
  *  Sets the connection parameters. Must be called before running the start_listener as a thread.
  *
  *  @param host - pointer to the host where the MQTT server is running
  *  @param port - the port number to connect, 1883 for non secure connections, 8883 for
  *                secure connections
  *  @param options - the connect data used for logging into the MQTT server.
  */
  void set_connection_parameters(const char *host, uint16_t port, MQTTPacket_connectData &options);

  int publish(const char *topic, const char *message, int qos = 0);

  void mqtt_publisher_task();

  void add_topic_handler(const char *topic, Callback<void(MessageData &)> func);

  // TODO: Add unsubscribe functionality.

  // Start the listener thread and start polling MQTT server.
  void start_listener();

  // Stop the listerner thread and closes connection
  void stop_listener();

  RtosLogger *logger();

 protected:
  // SSL/TLS variables
  mbedtls_entropy_context _entropy;
  mbedtls_ctr_drbg_context _ctr_drbg;
  mbedtls_x509_crt _cacert;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _ssl_conf;
  mbedtls_ssl_session _ssl_saved_session;

  /*
  * List of trusted root CA certificates
  * TODO: Move this certificate data onto the SD card.
  */
  static char DEFAULT_SSL_CA_PEM[];

  const char *DRBG_PERS;
  int handle_publish_message();
  void disconnect();
  int connect();

  static int ssl_recv(void *ctx, unsigned char *buf, size_t len);
  static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

 private:
  RtosLogger *_logger;
  NetworkInterface *_network;
  volatile bool _initialized;
  bool _use_tls;
  bool _ssl_cert_verify;
  const char *_ssl_ca_pem;
  TCPSocket *_tcpsocket;
  volatile PacketId packetid;
  std::string _host;
  uint16_t _port;
  MQTTPacket_connectData _connect_options;
  EventQueue _equeue;
  volatile bool _is_connected;
  volatile bool _is_running;
  volatile bool _has_saved_session;
  volatile bool _ping_request_sent;
  Ticker _mqtt_ticker;
  Mutex _lock;
  Thread _publisher_thread;

  // TODO: use a vector instead of maps to allow multiple handlers for the same topic.
  std::map<std::string, Callback<void(MessageData &)>> _topic_cb_map;

  unsigned char _sendbuf[MAX_MQTT_PACKET_SIZE];
  unsigned char _readbuf[MAX_MQTT_PACKET_SIZE];
  unsigned int _keepalive_interval;
  Timer _com_timer;

  void setup_tls();
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
  int send_publish(PubMessage &message);
  void reset_connection_timer();
  void send_ping_request();
  int has_connection_timed_out();
  int login();
  void mqtt_health_check();
};
}
#endif
