/*
PubSubClient.h - A simple client for MQTT.
Nicholas O'Leary
http://knolleary.net
*/

#include "mbed.h"
#include "TCPSocketConnection.h"

#ifndef PubSubClient_h
#define PubSubClient_h

// MQTT_MAX_PACKET_SIZE : Maximum packet size
#define MQTT_MAX_PACKET_SIZE 128

// MQTT_KEEPALIVE : keepAlive interval in Seconds
#define MQTT_KEEPALIVE 15000

#define MQTTPROTOCOLVERSION 3
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

class PubSubClient {
private:
  Timer t;
  TCPSocketConnection _client;
  char buffer[MQTT_MAX_PACKET_SIZE];
  int nextMsgId;
  unsigned long lastOutActivity;
  unsigned long lastInActivity;
  bool pingOutstanding;
  int millis();
  void (*callback)(char*,char*,unsigned int);
  int readPacket(int);
  char readByte();
  bool write(short header, char* buf, int length);
  int writeString(const char* string, char* buf, int pos);
  const char* ip;
  int port;
  
public:
  PubSubClient();
  PubSubClient(const char*, int, void(*)(char*,char*,unsigned int));
  void setOptions(const char*, int, void(*)(char*,char*,unsigned int));
  bool connect(const char *);
  bool connect(const char *, const char *, const char *);
  bool connect(const char *, const char *, short, short, const char *);
  bool connect(const char *, const char *, const char *, const char *, short, short, const char*);
  void disconnect();
  bool publish(const char *, const char *);
  bool publish(const char *, const char *, unsigned int);
  bool publish(const char *, const char *, unsigned int, bool);
  //   bool publish_P(char *, short PROGMEM *, unsigned int, bool);
  bool subscribe(const char *);
  bool unsubscribe(const char *);
  bool loop();
  bool connected();
};

#endif
