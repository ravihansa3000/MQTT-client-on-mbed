/*
PubSubClient.cpp - A simple client for MQTT.
Nicholas O'Leary
http://knolleary.net

initial port for mbed
Joerg Wende
https://twitter.com/joerg_wende

*/

#include "PubSubClient.h"

int PubSubClient::millis() {
  return t.read_ms();
}

PubSubClient::PubSubClient() {

}

PubSubClient::PubSubClient(const char *ip, int port, void (*callback)(char*,char*,unsigned int)) {
  this->callback = callback;
  this->ip = ip;
  this->port = port;
  t.start();
}

void PubSubClient::setOptions(const char *ip, int port, void (*callback)(char*,char*,unsigned int)) {
  this->callback = callback;
  this->ip = ip;
  this->port = port;
  t.start();
}

bool PubSubClient::connect(const char *id) {
  return connect(id,NULL,NULL,0,0,0,0);
}

bool PubSubClient::connect(const char *id, const char *user, const char *pass) {
  return connect(id,user,pass,0,0,0,0);
}

bool PubSubClient::connect(const char *id, const char* willTopic, short willQos, short willRetain, const char* willMessage) {
  return connect(id,NULL,NULL,willTopic,willQos,willRetain,willMessage);
}

bool PubSubClient::connect(const char *id, const char *user, const char *pass, const char* willTopic, short willQos, short willRetain, const char* willMessage) {
  if (!connected()) {
    int result = 0;
    result = _client.connect(this->ip, this->port);
    _client.set_blocking(false, 1);

    if (result==0) {
      nextMsgId = 1;
      char d[9] = {0x00,0x06,'M','Q','I','s','d','p',MQTTPROTOCOLVERSION};
      // Leave room in the buffer for header and variable length field
      int length = 5;
      unsigned int j;
      for (j = 0; j<9; j++) {
        buffer[length++] = d[j];
      }

      char v;
      if (willTopic) {
        v = 0x06|(willQos<<3)|(willRetain<<5);
      } else {
        v = 0x02;
      }

      if(user != NULL) {
        v = v|0x80;

        if(pass != NULL) {
          v = v|(0x80>>1);
        }
      }

      buffer[length++] = v;
      buffer[length++] = ((MQTT_KEEPALIVE) >> 8);
      buffer[length++] = ((MQTT_KEEPALIVE) & 0xFF);
      length = writeString(id,buffer,length);
      if (willTopic) {
        length = writeString(willTopic,buffer,length);
        length = writeString(willMessage,buffer,length);
      }

      if(user != NULL) {
        length = writeString(user,buffer,length);
        if(pass != NULL) {
          length = writeString(pass,buffer,length);
        }
      }

      write(MQTTCONNECT,buffer,length-5);

      lastInActivity = lastOutActivity = millis();

      int llen=128;
      int len =0;

      while ((len=readPacket(llen))==0) {
        unsigned long t = millis();
        if (t-lastInActivity > MQTT_KEEPALIVE*1000UL) {
          _client.close(true);
          return false;
        }
      }

      if (len == 4 && buffer[3] == 0) {
        lastInActivity = millis();
        pingOutstanding = false;
        return true;
      }
    }
    _client.close(true);
  }
  return false;
}


int PubSubClient::readPacket(int lengthLength) {
  int len = 0;
  len = _client.receive_all(buffer,lengthLength);
  return len;
}

bool PubSubClient::loop() {
  if (connected()) {
    unsigned long t = millis();
    if ((t - lastInActivity > MQTT_KEEPALIVE*1000UL) || (t - lastOutActivity > MQTT_KEEPALIVE*1000UL)) {
      if (pingOutstanding) {
        _client.close(true);
        return false;
      } else {
        buffer[0] = MQTTPINGREQ;
        buffer[1] = 0;
        _client.send(buffer,2);
        lastOutActivity = t;
        lastInActivity = t;
        pingOutstanding = true;
      }
    }
    int len;
    int llen= 128;
    if (!((len=readPacket(llen))==0)) {
      if (len > 0) {
        lastInActivity = t;
        char type = buffer[0]&0xF0;
        if (type == MQTTPUBLISH) {
          if (callback) {
            int tl = (buffer[2]<<8)+buffer[3];
            char topic[tl+1];
            for (int i=0; i<tl; i++) {
              topic[i] = buffer[4+i];
            }
            topic[tl] = 0;
            // ignore msgID - only support QoS 0 subs
            int t2 = len-4-tl;
            char payload[t2+1];
            for (int i=0; i<t2; i++) {
              payload[i] = buffer[4+i+tl];
            }
            payload[t2] = 0;
            callback(topic,payload,t2);
          }
        } else if (type == MQTTPINGREQ) {
          buffer[0] = MQTTPINGRESP;
          buffer[1] = 0;
          _client.send(buffer,2);
        } else if (type == MQTTPINGRESP) {
          pingOutstanding = false;
        }
      }
    }
    return true;
  }
  return false;
}

bool PubSubClient::publish(const char* topic, const char* payload) {
  return publish(topic,payload,strlen(payload),false);
}

bool PubSubClient::publish(const char* topic, const char* payload, unsigned int plength) {
  return publish(topic, payload, plength, false);
}

bool PubSubClient::publish(const char* topic, const char* payload, unsigned int plength, bool retained) {
  if (connected()) {
    // Leave room in the buffer for header and variable length field
    int length = 5;
    length = writeString(topic,buffer,length);
    int i;
    for (i=0; i<plength; i++) {
      buffer[length++] = payload[i];
    }
    short header = MQTTPUBLISH;
    if (retained) {
      header |= 1;
    }
    return write(header,buffer,length-5);
  }
  return false;
}


bool PubSubClient::write(short header, char* buf, int length) {
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
  } while(len>0);

  buf[4-llen] = header;
  for (int i=0; i<llen; i++) {
    buf[5-llen+i] = lenBuf[i];
  }
  rc = _client.send(buf+(4-llen),length+1+llen);

  lastOutActivity = millis();
  return (rc == 1+llen+length);
}

bool PubSubClient::subscribe(const char* topic) {
  if (connected()) {
    // Leave room in the buffer for header and variable length field
    int length = 5;
    nextMsgId++;
    if (nextMsgId == 0) {
      nextMsgId = 1;
    }
    buffer[length++] = (nextMsgId >> 8);
    buffer[length++] = (nextMsgId & 0xFF);
    length = writeString(topic, buffer,length);
    buffer[length++] = 0; // Only do QoS 0 subs
    return write(MQTTSUBSCRIBE|MQTTQOS1,buffer,length-5);
  }
  return false;
}

bool PubSubClient::unsubscribe(const char* topic) {
  if (connected()) {
    int length = 5;
    nextMsgId++;
    if (nextMsgId == 0) {
      nextMsgId = 1;
    }
    buffer[length++] = (nextMsgId >> 8);
    buffer[length++] = (nextMsgId & 0xFF);
    length = writeString(topic, buffer,length);
    return write(MQTTUNSUBSCRIBE|MQTTQOS1,buffer,length-5);
  }
  return false;
}

void PubSubClient::disconnect() {
  buffer[0] = MQTTDISCONNECT;
  buffer[1] = 0;
  _client.send(buffer,2);
  _client.close(true);
  lastInActivity = lastOutActivity = millis();
}

int PubSubClient::writeString(const char* string, char* buf, int pos) {
  const char* idp = string;
  int i = 0;
  pos += 2;
  while (*idp) {
    buf[pos++] = *idp++;
    i++;
  }
  buf[pos-i-2] = (i >> 8);
  buf[pos-i-1] = (i & 0xFF);
  return pos;
}


bool PubSubClient::connected()
{
  bool rc;
  rc = (int)_client.is_connected();
  if (!rc) _client.close(true);
  return rc;
}
