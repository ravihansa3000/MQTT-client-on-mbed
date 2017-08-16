/*
PubSubClient.h - A simple client for MQTT.

Akila Ravihansa Perera

Nicholas O'Leary
http://knolleary.net
*/

#ifndef PUBSUB_CLIENT_H
#define PUBSUB_CLIENT_H

#include "mbed.h"
#include "RtosLogger.h"
#include "TCPSocket.h"

#define MQTT_VERSION_3_1      3
#define MQTT_VERSION_3_1_1    4

#ifndef MQTT_VERSION
#define MQTT_VERSION MQTT_VERSION_3_1_1
#endif

#define MQTT_MAX_PACKET_SIZE 256 // Maximum packet size
#define MQTT_KEEPALIVE 60 // Keep-alive interval in Seconds

#define MQTTCONNECT 1 << 4 // Client request to connect to Server
#define MQTTCONNACK 2 << 4 // Connect Acknowledgment
#define MQTTPUBLISH 3 << 4 // Publish message
#define MQTTPUBACK 4 << 4 // Publish Acknowledgment
#define MQTTPUBREC 5 << 4 // Publish Received (assured delivery part 1)
#define MQTTPUBREL 6 << 4 // Publish Release (assured delivery part 2)
#define MQTTPUBCOMP 7 << 4 // Publish Complete (assured delivery part 3)
#define MQTTSUBSCRIBE 8 << 4 // Client Subscribe request
#define MQTTSUBACK 9 << 4 // Subscribe Acknowledgment
#define MQTTUNSUBSCRIBE 10 << 4 // Client Unsubscribe request
#define MQTTUNSUBACK 11 << 4 // Unsubscribe Acknowledgment
#define MQTTPINGREQ 12 << 4 // PING Request
#define MQTTPINGRESP 13 << 4 // PING Response
#define MQTTDISCONNECT 14 << 4 // Client is Disconnecting
#define MQTTReserved 15 << 4 // Reserved

#define MQTTQOS0 (0 << 1)
#define MQTTQOS1 (1 << 1)
#define MQTTQOS2 (2 << 1)

#define MQTT_ERROR_NO_CONNECTION -1001
#define MQTT_ERROR_PARAMETER -1002
#define MQTT_MALFORMED_REMAINING_LENGTH -1003

#if defined(MQTT_ENABLE_DEBUG_MODE)
#define PUBSUB_DBG(x, ...) _logger->printf_time("[DEBUG][PUBSUB] " x "\r\n", ##__VA_ARGS__);
#else
#define PUBSUB_DBG(x, ...)
#endif

#define PUBSUB_INFO(x, ...) _logger->printf_time("[INFO][PUBSUB] " x "\r\n", ##__VA_ARGS__);
#define PUBSUB_WARN(x, ...) _logger->printf_time("[WARN][PUBSUB] " x "\r\n", ##__VA_ARGS__);
#define PUBSUB_ERR(x, ...) _logger->printf_time("[ERROR][PUBSUB] " x "\r\n", ##__VA_ARGS__);

class PubSubClient {

private:

  TCPSocket _socket;
  Timer _timer;
  const char* _ip;
  int _port;
  RtosLogger* _logger;
  bool _is_connected;
  NetworkInterface *_iface;
  void (*_callback)(char*, uint8_t*, unsigned int);
  uint8_t buffer[MQTT_MAX_PACKET_SIZE + 1];
  uint16_t nextMsgId;
  unsigned long lastOutActivity;
  unsigned long lastInActivity;
  bool pingOutstanding;

  int millis();
  int readPacket(uint8_t*);
  char readByte();
  bool write(short header, uint8_t* buf, int length);
  int writeString(const char* string, uint8_t* buf, int pos);
  int mqtt_event_handler();

public:

  PubSubClient(RtosLogger *logger, NetworkInterface *iface, const char *ip, int port, void (*callback)(char*, uint8_t*, unsigned int));
  ~PubSubClient();
  void setOptions(const char*, int, void(*)(char*, uint8_t*, unsigned int));
  int connect(const char *);
  int connect(const char *, const char *, const char *);
  int connect(const char *, const char *, short, short, const char *);
  int connect(const char *, const char *, const char *, const char *, short, short, const char*);
  void disconnect();
  bool publish(const char *, const char *);
  bool publish(const char *, const char *, unsigned int);
  bool publish(const char *, const char *, unsigned int, bool);
  bool subscribe(const char *);
  bool subscribe(const char*, int);
  bool unsubscribe(const char *);
  int loop();
  bool connected();
  void dispatch_events();
};

#endif
