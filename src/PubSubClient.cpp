/*
PubSubClient.cpp - A simple client for MQTT.

Akila Ravihansa Perera

Nicholas O'Leary
http://knolleary.net

initial port for mbed
Joerg Wende
https://twitter.com/joerg_wende

*/

#include "PubSubClient.h"

int PubSubClient::millis() {
  return _timer.read_ms();
}

PubSubClient::PubSubClient(RtosLogger *logger, NetworkInterface *iface, const char *ip, int port, void (*callback)(char*, uint8_t*, unsigned int)) :
_ip(ip),
_port(port),
_logger(logger),
_is_connected(false),
_iface(iface),
_callback(callback) {
  _timer.start();
}

PubSubClient::~PubSubClient() {
}

void PubSubClient::setOptions(const char *ip, int port, void (*callback)(char*, uint8_t*, unsigned int)) {
  this->_callback = callback;
  this->_ip = ip;
  this->_port = port;
}

int PubSubClient::connect(const char *id) {
  return connect(id, NULL, NULL, 0, 0, 0, 0);
}

int PubSubClient::connect(const char *id, const char *user, const char *pass) {
  return connect(id, user, pass, 0, 0, 0, 0);
}

int PubSubClient::connect(const char *id, const char* willTopic, short willQos, short willRetain, const char* willMessage) {
  return connect(id, NULL, NULL, willTopic, willQos, willRetain, willMessage);
}

int PubSubClient::connect(const char *id, const char *user, const char *pass, const char* willTopic, short willQos, short willRetain, const char* willMessage) {
  if (!connected()) {
    PUBSUB_INFO("Trying to connect to MQTT server [host] %s, [port] %d", this->_ip, this->_port);
    _socket.open(_iface);
    _socket.set_timeout(1000);
    int result = _socket.connect(this->_ip, this->_port);
    if (result == 0) {
      nextMsgId = 1;
      int length = 5; // Leave room in the buffer for header and variable length field
      unsigned int j;

      #if MQTT_VERSION == MQTT_VERSION_3_1
      uint8_t d[9] = {0x00,0x06,'M','Q','I','s','d','p', MQTT_VERSION};
      #define MQTT_HEADER_VERSION_LENGTH 9
      #elif MQTT_VERSION == MQTT_VERSION_3_1_1
      uint8_t d[7] = {0x00,0x04,'M','Q','T','T',MQTT_VERSION};
      #define MQTT_HEADER_VERSION_LENGTH 7
      #endif

      for (j = 0; j < MQTT_HEADER_VERSION_LENGTH; j++) {
        buffer[length++] = d[j];
      }

      char v;
      if (willTopic) {
        v = 0x06 | (willQos << 3) | (willRetain << 5);
      } else {
        v = 0x02;
      }

      if(user != NULL) {
        v = v | 0x80;

        if(pass != NULL) {
          v = v | (0x80 >> 1);
        }
      }

      buffer[length++] = v;
      buffer[length++] = ((MQTT_KEEPALIVE) >> 8);
      buffer[length++] = ((MQTT_KEEPALIVE) & 0xFF);
      length = writeString(id, buffer, length);
      if (willTopic) {
        length = writeString(willTopic, buffer, length);
        length = writeString(willMessage, buffer, length);
      }

      if(user != NULL) {
        length = writeString(user, buffer, length);
        if(pass != NULL) {
          length = writeString(pass, buffer, length);
        }
      }

      write(MQTTCONNECT, buffer, length - 5);
      lastInActivity = lastOutActivity = millis();
      uint8_t llen = 0;
      int len = 0;

      while ((len = readPacket(&llen)) == 0 || len == NSAPI_ERROR_WOULD_BLOCK) {
        unsigned long t = millis();
        if (t - lastInActivity > MQTT_KEEPALIVE * 1000UL) {
          _socket.close();
          PUBSUB_ERR("Connection timed out while connecting to MQTT server ... [FAIL]");
          return result;
        }
      }

      if (len == 4 && buffer[3] == 0) {
        lastInActivity = millis();
        pingOutstanding = false;
        _is_connected = true;
        return result;
      } else {
        _socket.close();
        PUBSUB_ERR("Invalid response at MQTT connect: [len] %d, [buffer@3] %d", len, buffer[3]);
        return result;
      }
    } else {
      _socket.close();
      PUBSUB_ERR("Could not connect to MQTT server (error code: %d)... [FAIL]", result);
      return result;
    }
  } else {
    PUBSUB_WARN("Already connected to MQTT server, invalid call.");
    return MQTT_ERROR_PARAMETER;
  }
}


int PubSubClient::readPacket(uint8_t* lengthLength) {
  int len = 0;
  len = _socket.recv(buffer, MQTT_MAX_PACKET_SIZE);
  int index = 1; // start from 2nd byte, skip 1st byte in fixed header
  uint32_t multiplier = 1;
  uint16_t value = 0;
  uint8_t digit = 0;
  do {
    digit = buffer[index++];
    value += (digit & 127) * multiplier;
    multiplier *= 128;
    if (multiplier > 128*128*128) {
      return MQTT_MALFORMED_REMAINING_LENGTH;
    }
  } while ((digit & 128) != 0);
  *lengthLength = index - 1;
  buffer[len] = 0; // end the payload as a 'C' string with \x00
  return len;
}

int PubSubClient::mqtt_event_handler() {
  int len = 0;
  uint8_t llen = 0;
  uint8_t *payload;

  if (!((len = readPacket(&llen)) == 0)) {
    if (len > 0) {
      lastInActivity = millis();
      char type = buffer[0] & 0xF0;

      if (type == MQTTPUBLISH) {
        if (_callback) {
          int tl = (buffer[llen + 1] << 8) + buffer[llen + 2]; // topic length in bytes
          memmove(buffer + llen + 2, buffer + llen + 3, tl); // move topic inside buffer 1 byte to front
          buffer[llen + 2 + tl] = 0; // end the topic as a 'C' string with \x00
          char *topic = (char*) buffer + llen + 2;
          if ((buffer[0]&0x06) == MQTTQOS1) { // msgId only present for QOS>0
            uint16_t msgId = (buffer[llen + 3 + tl] << 8) + buffer[llen + 3 + tl + 1];
            payload = buffer + llen + 3 + tl + 2;
            PUBSUB_DBG("MQTTPUBLISH QOS1 [len] %d, [llen] %d, [tl] %d", len, llen, tl);
            _callback(topic, payload, len - llen - 3 - tl - 2);
            buffer[0] = MQTTPUBACK;
            buffer[1] = 2;
            buffer[2] = (msgId >> 8);
            buffer[3] = (msgId & 0xFF);
            _socket.send(buffer, 4);
            lastOutActivity = millis();
          } else {
            payload = buffer + llen + 3 + tl;
            PUBSUB_DBG("MQTTPUBLISH QOS0 [len] %d, [llen] %d, [tl] %d", len, llen, tl);
            _callback(topic, payload, len - llen - 3 - tl);
          }
        }
      } else if (type == MQTTPINGREQ) {
        buffer[0] = MQTTPINGRESP;
        buffer[1] = 0;
        _socket.send(buffer, 2);
      } else if (type == MQTTPINGRESP) {
        pingOutstanding = false;
      }
    }
  }
  return len;
}

int PubSubClient::loop() {
  if (connected()) {
    unsigned long t = millis();
    if ((t - lastInActivity > MQTT_KEEPALIVE * 1000UL) || (t - lastOutActivity > MQTT_KEEPALIVE * 1000UL)) {
      if (pingOutstanding) {
        _socket.close();
        _is_connected = false;
        PUBSUB_ERR("MQTT client disconnected due to inactivity. Keep alive exceeded: [keep-alive] %d", MQTT_KEEPALIVE);
        return MQTT_ERROR_NO_CONNECTION;
      } else {
        buffer[0] = MQTTPINGREQ;
        buffer[1] = 0;
        _socket.send(buffer, 2);
        lastOutActivity = t;
        lastInActivity = t;
        pingOutstanding = true;
      }
    }
    int rc = mqtt_event_handler();
    if (rc >= 0 || rc == NSAPI_ERROR_WOULD_BLOCK) {
      return rc;
    } else { // connection error
      _socket.close();
      _is_connected = false;
      PUBSUB_ERR("MQTT client disconnected due to network error (error code: %d)", rc);
      return rc;
    }
  } else {
    PUBSUB_ERR("MQTT client is not connected.");
    return MQTT_ERROR_NO_CONNECTION;
  }
}

bool PubSubClient::publish(const char* topic, const char* payload) {
  return publish(topic, payload, strlen(payload), false);
}

bool PubSubClient::publish(const char* topic, const char* payload, unsigned int plength) {
  return publish(topic, payload, plength, false);
}

bool PubSubClient::publish(const char* topic, const char* payload, unsigned int plength, bool retained) {
  if (connected()) {
    if (MQTT_MAX_PACKET_SIZE < 5 + 2 + strlen(topic) + plength) {
      PUBSUB_ERR("Could not publish message, packet is too long.");
      return false;
    }
    int length = 5; // Leave room in the buffer for header and variable length field
    length = writeString(topic, buffer, length);
    int i;
    for (i = 0; i < (int)plength; i++) {
      buffer[length++] = payload[i];
    }
    short header = MQTTPUBLISH;
    if (retained) {
      header |= 1;
    }
    return write(header, buffer, length - 5);
  }
  return false;
}


bool PubSubClient::write(short header, uint8_t* buf, int length) {
  short lenBuf[4];
  short llen = 0;
  short digit;
  short pos = 0;
  short rc;
  short len = length;
  do {
    digit = len % 128;
    len = len / 128;
    if (len > 0) {
      digit |= 0x80;
    }
    lenBuf[pos++] = digit;
    llen++;
  } while(len > 0);

  buf[4 - llen] = header;
  for (int i = 0; i < llen; i++) {
    buf[5 - llen + i] = lenBuf[i];
  }
  rc = _socket.send(buf + (4 - llen), length + 1 + llen);

  lastOutActivity = millis();
  return (rc == 1 + llen + length);
}

bool PubSubClient::subscribe(const char* topic) {
  return subscribe(topic, 0);
}

bool PubSubClient::subscribe(const char* topic, int qos) {
  if (qos < 0 || qos > 1) {
    return false;
  }
  if (MQTT_MAX_PACKET_SIZE < 9 + strlen(topic)) {
    PUBSUB_ERR("Could not subscribe, topic is too long.");
    return false;
  }
  if (connected()) {    
    int length = 5; // Leave room in the buffer for header and variable length field
    nextMsgId++;
    if (nextMsgId == 0) {
      nextMsgId = 1;
    }
    buffer[length++] = (nextMsgId >> 8);
    buffer[length++] = (nextMsgId & 0xFF);
    length = writeString((char*)topic, buffer, length);
    buffer[length++] = qos;
    return write(MQTTSUBSCRIBE | MQTTQOS1, buffer, length - 5);
  }
  return false;
}

bool PubSubClient::unsubscribe(const char* topic) {
  if (MQTT_MAX_PACKET_SIZE < 9 + strlen(topic)) {
    PUBSUB_ERR("Could not publish message, packet is too long.");
    return false;
  }
  if (connected()) {
    int length = 5;
    nextMsgId++;
    if (nextMsgId == 0) {
      nextMsgId = 1;
    }
    buffer[length++] = (nextMsgId >> 8);
    buffer[length++] = (nextMsgId & 0xFF);
    length = writeString(topic, buffer, length);
    return write(MQTTUNSUBSCRIBE | MQTTQOS1, buffer, length - 5);
  }
  return false;
}

void PubSubClient::disconnect() {
  buffer[0] = MQTTDISCONNECT;
  buffer[1] = 0;
  _socket.send(buffer, 2);
  _socket.close();
  lastInActivity = lastOutActivity = millis();
  _is_connected = false;
  PUBSUB_DBG("MQTT client disconnected.");
}

int PubSubClient::writeString(const char* string, uint8_t* buf, int pos) {
  const char* idp = string;
  int i = 0;
  pos += 2;
  while (*idp) {
    buf[pos++] = *idp++;
    i++;
  }
  buf[pos - i - 2] = (i >> 8);
  buf[pos - i - 1] = (i & 0xFF);
  return pos;
}

bool PubSubClient::connected() {
  return _is_connected;
}
