#include "MQTTClient.h"

namespace MQTT {

static void donothing(MessageData &md) {}

/**
* Read until a specified packet type is received, or untill the specified
* timeout dropping packets along the way.
**/
int MQTTClient::read_until(int packet_type, int timeout) {
  int type = FAILURE;
  Timer timer;
  timer.start();
  do {
    type = read_packet();
    if (type < 0 && type != NSAPI_ERROR_WOULD_BLOCK) {
      break;
    }

    if (timer.read_ms() > timeout) {
      type = FAILURE;
      break;
    }
  } while (type != packet_type);

  return type;
}

void MQTTClient::set_connection_parameters(const char *host, uint16_t port, MQTTPacket_connectData &options) {
  _host = host;
  _port = port;
  _connect_options = options;
}

int MQTTClient::publish(const char *topic, const char *message, int qos) {
  PubMessage pub_message;
  pub_message.qos = (QoS)qos;
  pub_message.id = (int)packetid.get_next();
  strcpy(&pub_message.topic[0], topic);
  strcpy(&pub_message.payload[0], message);
  pub_message.payloadlen = strlen((const char *)&pub_message.payload[0]);

  int id = _equeue.call(callback(this, &MQTTClient::send_publish), pub_message);
  if (id == 0) {
    ERR("Could not add to publish queue ... [FAIL]");
    return FAILURE;
  } else {
    return SUCCESS;
  }
}

int MQTTClient::send_publish(PubMessage &message) {
  if (!_is_connected) {
    ERR("Could not send queued publish message, not connected ... [FAIL]");
    return FAILURE;
  }
  MQTTString mqtt_topic = MQTTString_initializer;
  mqtt_topic.cstring = (char *)&message.topic[0];
  _lock.lock();
  int len = MQTTSerialize_publish(_sendbuf, MAX_MQTT_PACKET_SIZE, 0, message.qos, false, message.id, mqtt_topic,
                                  (unsigned char *)&message.payload[0], (int)message.payloadlen);
  if (len <= 0) {
    ERR("Failed serializing publish message (error code: %d) ... [FAIL]", len);
    _lock.unlock();
    return FAILURE;
  }
  int rc = send_packet(len);
  _lock.unlock();
  if (rc == SUCCESS) {
    // reset_connection_timer(); // reset timers if we have been able to send successfully
    // TODO: troubleshoot mbedOS bug: send packet returns success although connection is broken
    DBG("Successfully published message, [topic] %s, [payload] %s, [qos] %d", message.topic, message.payload,
        message.qos);
    Thread::wait(50);
    return SUCCESS;
  }
  ERR("Failed to send queued publish message to server (error code: %d), disconnecting ... [FAIL]", rc);
  disconnect();
  return FAILURE;
}

void MQTTClient::add_topic_handler(const char *topic, Callback<void(MessageData &)> func) {
  if (func) {
    _topic_cb_map.insert(std::pair<std::string, Callback<void(MessageData &)>>(std::string(topic), func));
  } else {
    _topic_cb_map.insert(
        std::pair<std::string, Callback<void(MessageData &)>>(std::string(topic), callback(donothing)));
  }
}

int MQTTClient::process_subscriptions() {
  if (!_is_connected) {
    ERR("Session not connected ... [FAIL]");
    return 0;
  }

  DBG("Processing subscribed topics...");

  std::map<std::string, Callback<void(MessageData &)>>::iterator it;
  for (it = _topic_cb_map.begin(); it != _topic_cb_map.end(); it++) {
    int len = 0;
    // TODO: We only subscribe to QoS = 0 for now
    QoS qos = QOS0;
    MQTTString topic = {(char *)it->first.c_str(), {0, 0}};
    DBG("Subscribing to topic [%s]", topic.cstring);
    _lock.lock();
    len = MQTTSerialize_subscribe(_sendbuf, MAX_MQTT_PACKET_SIZE, 0, packetid.get_next(), 1, &topic, (int *)&qos);
    if (len <= 0) {
      ERR("Error serializing subscribe packet (error code: %d) ... [FAIL]", len);
      _lock.unlock();
      return FAILURE;
    }
    int rc = send_packet(len);
    _lock.unlock();
    if (rc != SUCCESS) {
      ERR("Error sending subscribe packet. [topic] %s, [rc] %d ... [FAIL]", topic.cstring, rc);
      return rc;
    }

    DBG("Waiting for subscription ack...");
    // Wait for SUBACK, dropping packets read along the way ...
    if (read_until(SUBACK, COMMAND_TIMEOUT) == SUBACK) {  // wait for suback
      int count = 0, grantedQoS = -1;
      unsigned short mypacketid;
      if (MQTTDeserialize_suback(&mypacketid, 1, &count, &grantedQoS, _readbuf, MAX_MQTT_PACKET_SIZE) == 1) {
        rc = grantedQoS;  // 0, 1, 2 or 0x80
      }
      // For as long as we do not get 0x80 ..
      if (rc != 0x80) {
        reset_connection_timer();  // SUB and SUBACK sequence complete
        INFO("Successfully subscribed to %s ... [OK]", it->first.c_str());
      } else {
        ERR("Failed to subscribe to topic %s ... (not authorized?) ... [FAIL]", it->first.c_str());
        return FAILURE;
      }
    } else {
      ERR("Failed to subscribe to topic %s (ack not received) ... [FAIL]", it->first.c_str());
      return FAILURE;
    }
  }  // end for loop

  return SUCCESS;
}

bool MQTTClient::is_topic_matched(char *filter, MQTTString &mqtt_topic) {
  char *curf = filter;
  char *curn = mqtt_topic.lenstring.data;
  char *curn_end = curn + mqtt_topic.lenstring.len;

  while (*curf && curn < curn_end) {
    if (*curn == '/' && *curf != '/') break;
    if (*curf != '+' && *curf != '#' && *curf != *curn) break;
    if (*curf == '+') {  // skip until we meet the next separator, or end of string
      char *nextpos = curn + 1;
      while (nextpos < curn_end && *nextpos != '/') nextpos = ++curn + 1;
    } else if (*curf == '#') {  // skip until end of string
      curn = curn_end - 1;
    }
    curf++;
    curn++;
  };

  return (curn == curn_end) && (*curf == '\0');
}

int MQTTClient::handle_publish_message() {
  MQTTString mqtt_topic = MQTTString_initializer;
  Message msg;
  int intQoS;
  DBG("Deserializing publish message...");
  if (MQTTDeserialize_publish((unsigned char *)&msg.dup, &intQoS, (unsigned char *)&msg.retained,
                              (unsigned short *)&msg.id, &mqtt_topic, (unsigned char **)&msg.payload,
                              (int *)&msg.payloadlen, _readbuf, MAX_MQTT_PACKET_SIZE) != 1) {
    ERR("Error deserializing published message ... [FAIL]");
    return -1;
  }

  std::string topic;
  if (mqtt_topic.lenstring.len > 0) {
    topic = std::string((const char *)mqtt_topic.lenstring.data, (size_t)mqtt_topic.lenstring.len);
  } else {
    topic = (const char *)mqtt_topic.cstring;
  }
  DBG("Got message for topic [%s], QoS [%d]", topic.c_str(), intQoS);
  msg.qos = (QoS)intQoS;
  // Call the handlers for each topic
  if (_topic_cb_map.find(topic) != _topic_cb_map.end()) {  // Call the callback function
    DBG("Invoking function handler for topic...");
    MessageData md(mqtt_topic, msg);
    _topic_cb_map[topic].call(md);
    return 1;
  }

  // TODO: depending on the QoS
  // we send data to the server = PUBACK or PUBREC
  switch (intQoS) {
    case QOS0:  // send back nothing
      break;

    case QOS1:
      // TODO: implement
      break;

    case QOS2:
      // TODO: implement
      break;

    default:
      break;
  }

  return 0;
}

void MQTTClient::reset_connection_timer() {
  if (_keepalive_interval > 0) {
    _com_timer.reset();
    _com_timer.start();
    _ping_request_sent = false;
  }
}

int MQTTClient::has_connection_timed_out() {
  if (_keepalive_interval > 0) {  // check connection timer
    if ((unsigned int)_com_timer.read_ms() > (2 * _keepalive_interval)) {
      return -2;
    } else if ((unsigned int)_com_timer.read_ms() > _keepalive_interval) {
      return -1;
    } else {
      return 0;
    }
  }
  return 0;
}

void MQTTClient::send_ping_request() {
  if (!_is_connected) {
    ERR("Could not send ping request, not connected ... [FAIL]");
    return;
  }
  _lock.lock();
  int len = MQTTSerialize_pingreq(_sendbuf, MAX_MQTT_PACKET_SIZE);
  if (len <= 0) {
    ERR("Failed serializing ping request message (error code: %d) ... [FAIL]", len);
    _lock.unlock();
    return;
  }
  int rc = send_packet(len);
  _lock.unlock();
  if (rc == SUCCESS) {  // send the ping packet
    // reset_connection_timer(); // reset timers if we have been able to send successfully
    // TODO: troubleshoot mbedOS bug: send packet returns success although connection is broken
    _ping_request_sent = true;
    DBG("Ping request sent successfully ... [OK]");
  } else {
    disconnect();
    ERR("Error sending ping request (error code: %d) ... [FAIL]", rc);
  }
}

RtosLogger *MQTTClient::logger() { return _logger; }

void MQTTClient::mqtt_health_check() {
  int rc = has_connection_timed_out();
  if (rc == -2) {
    ERR("MQTT health check found MQTT server to be unresponsive, disconnecting ... [FAIL]");
    disconnect();
  }
  DBG("MQTT health check task executed: [timed_out] %d, [timer_ms] %u, [keep_alive] %d", rc, _com_timer.read_ms(),
      _keepalive_interval);
}
}
