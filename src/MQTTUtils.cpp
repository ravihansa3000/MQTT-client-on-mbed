#include "MQTTClient.h"

namespace MQTT {

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

int MQTTClient::process_subscriptions() {
  if (!_is_connected) {
    ERR("Session not connected ... [FAIL]");
    return FAILURE;
  }

  DBG("Processing subscribed topics...");

  for (int i = 0; i < MAX_MQTT_MESSAGE_HANDLERS; i++) {
    if (_message_handlers[i].topic_filter == 0) {
      continue;
    }
    int len = 0;
    // TODO: We only subscribe to QoS = 0 for now
    QoS qos = QOS0;
    MQTTString topic = {(char *)_message_handlers[i].topic_filter, {0, 0}};
    DBG("Subscribing to topic [%s]", topic.cstring);
    len = MQTTSerialize_subscribe(_sendbuf, MAX_MQTT_PACKET_SIZE, 0, _packetid.get_next(), 1, &topic, (int *)&qos);
    if (len <= 0) {
      ERR("Error serializing subscribe packet (error code: %d) ... [FAIL]", len);
      return FAILURE;
    }
    int rc = send_packet(len);
    if (rc != SUCCESS) {
      ERR("Error sending subscribe packet. [topic] %s, [rc] %d ... [FAIL]", topic.cstring, rc);
      return rc;
    }
    wait_ms(10);

    DBG("Waiting for subscription ack...");
    // Wait for SUBACK, dropping packets read along the way ...
    if (read_until(SUBACK, MQTT_COMMAND_TIMEOUT) == SUBACK) {  // wait for suback
      int count = 0, grantedQoS = -1;
      unsigned short suback_packetid;
      if (MQTTDeserialize_suback(&suback_packetid, 1, &count, &grantedQoS, _readbuf, MAX_MQTT_PACKET_SIZE) == 1) {
        rc = grantedQoS;  // 0, 1, 2 or 0x80
      }
      // For as long as we do not get 0x80 ..
      if (rc != 0x80) {
        reset_connection_timer();  // SUB and SUBACK sequence complete
        INFO("Successfully subscribed to %s ... [OK]", _message_handlers[i].topic_filter);
      } else {
        ERR("Failed to subscribe to topic %s ... (not authorized?) ... [FAIL]", _message_handlers[i].topic_filter);
        return FAILURE;
      }
    } else {
      ERR("Failed to subscribe to topic %s (ack not received) ... [FAIL]", _message_handlers[i].topic_filter);
      return FAILURE;
    }
  }  // end for loop

  return SUCCESS;
}

bool MQTTClient::is_topic_matched(char *topic_filter, MQTTString &mqtt_topic) {
  char *curf = topic_filter;
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
  int rc = FAILURE;
  MQTTString mqtt_topic = MQTTString_initializer;
  int intQoS;
  void *payload_ptr;
  MQTTMessage message;
  DBG("Deserializing publish message...");
  if (MQTTDeserialize_publish((unsigned char *)&message.dup, &intQoS, (unsigned char *)&message.retained,
                              (unsigned short *)&message.id, &mqtt_topic, (unsigned char **)&payload_ptr,
                              (int *)&message.payloadlen, _readbuf, MAX_MQTT_PACKET_SIZE) != 1) {
    ERR("Error deserializing published message ... [FAIL]");
    return -1;
  }

  message.qos = (QoS)intQoS;
  if (mqtt_topic.lenstring.len > 0) {
    if (mqtt_topic.lenstring.len > MAX_MQTT_TOPIC_SIZE) {
      ERR("Error handling publish message, topic length exceeds max limit: [len] %d, [max] %d", mqtt_topic,
          MAX_MQTT_TOPIC_SIZE);
      return BUFFER_OVERFLOW;
    }
    snprintf(message.topic, mqtt_topic.lenstring.len + 1, "%s", mqtt_topic.lenstring.data);
  } else {
    snprintf(message.topic, sizeof(message.topic), "%s", mqtt_topic.cstring);
  }

  if (message.payloadlen > MAX_MQTT_PAYLOAD_SIZE) {
    ERR("Error handling publish message, payload length exceeds max limit: [len] %d, [max] %d", message.payloadlen,
        MAX_MQTT_PAYLOAD_SIZE);
    return BUFFER_OVERFLOW;
  }
  snprintf(message.payload, message.payloadlen + 1, "%s", (const char *)payload_ptr);
  DBG("Handling MQTT PUB message: [topic] %s, [payload] %s, [payloadlen] %d, [QoS] %d", message.topic, message.payload,
      message.payloadlen, message.qos);

  if (intQoS != QOS0) {  // TODO: only QoS0 is supported for now
    ERR("Error handling publish message, unsupported QoS: [topic] %s, [payload] %s, [QoS] %d", message.topic,
        message.payload, message.qos);
    return FAILURE;
  }

  // Call the handlers for each topic
  for (int i = 0; i < MAX_MQTT_MESSAGE_HANDLERS; i++) {
    if (_message_handlers[i].topic_filter != 0 &&
        (MQTTPacket_equals(&mqtt_topic, (char *)_message_handlers[i].topic_filter) ||
         is_topic_matched((char *)_message_handlers[i].topic_filter, mqtt_topic))) {
      if (_message_handlers[i].topic_cb) {
        DBG("Invoking function handler for topic...");
        _message_handlers[i].topic_cb.call(message);
        rc = SUCCESS;
      }
    }
  }

  // Depending on the QoS send data to the MQTT broker; PUBACK or PUBREC
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

  return rc;
}

void MQTTClient::reset_connection_timer() {
  if (_keepalive_interval > 0) {
    _timer.reset();
    _timer.start();
    _ping_request_sent = false;
  }
}

int MQTTClient::has_connection_timed_out() {
  if (_keepalive_interval > 0) {  // check connection timer only if keep alive is set
    if ((unsigned int)_timer.read_ms() > (2 * _keepalive_interval)) {
      return -2;  // PING response not received during grace period, MQTT broker unresponsive
    } else if ((unsigned int)_timer.read_ms() > _keepalive_interval) {
      return -1;  // keep alive expired, time to send a PING request
    } else {
      return 0;  // keep alive has not expired
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
    _lock.unlock();
    ERR("Failed serializing ping request message (error code: %d) ... [FAIL]", len);
    return;
  }
  int rc = send_packet(len);
  _lock.unlock();

  if (rc == SUCCESS) {
    // reset_connection_timer();  // reset timers if we have been able to send successfully
    // TODO: troubleshoot mbedOS bug: send packet returns success although connection is broken
    _ping_request_sent = true;
    DBG("MQTT client ping request sent successfully ... [OK]");
  } else {
    ERR("Failed to send MQTT client ping request (error code: %d). MQTT client will disconnect ... [FAIL]", rc);
    disconnect();
  }
}

void MQTTClient::clear_send_buffer() {
  _lock.lock();
  int count = 0;
  for (int i = 0; i < MAX_MQTT_PUBLISH_MESSAGES; i++) {
    if (_publishbuf[i].pub_timer.read_ms() > MQTT_PUBLISH_TIMEOUT) {
      _publishbuf[i].pub_message.id = 0;
      _publishbuf[i].pub_timer.stop();
      _publishbuf[i].pub_timer.reset();
      count++;
    }
  }
  _lock.unlock();
  DBG("MQTT send buffer cleared, %d stale messages removed.", count);
}

void MQTTClient::mqtt_health_check() {
  if (_is_connected) {
    int rc = has_connection_timed_out();
    if (rc == -1 && _ping_request_sent == false) {
      DBG("MQTT keep alive expired, sending ping request...");
      send_ping_request();
    } else if (rc == -2) {
      ERR("MQTT broker is unresponsive, MQTT client will disconnect ... [FAIL]");
      disconnect();
    }
    DBG("MQTT health check task executed: [timed_out] %d, [timer_ms] %u, [keep_alive] %d", rc, _timer.read_ms(),
        _keepalive_interval);
  }
}

void MQTTClient::clean_session() {
  for (int i = 0; i < MAX_MQTT_MESSAGE_HANDLERS; ++i) {
    _message_handlers[i].topic_filter = 0;
  }

  for (int i = 0; i < MAX_MQTT_PUBLISH_MESSAGES; ++i) {
    _publishbuf[i].pub_message.id = 0;
    _publishbuf[i].pub_timer.stop();
    _publishbuf[i].pub_timer.reset();
  }

#if MQTTCLIENT_QOS1 || MQTTCLIENT_QOS2
  inflightMsgid = 0;
  inflightQoS = QOS0;
#endif

#if MQTTCLIENT_QOS2
  pubrel = false;
  for (int i = 0; i < MAX_INCOMING_QOS2_MESSAGES; ++i) {
    incomingQoS2messages[i] = 0;
  }
#endif
}

#if MQTTCLIENT_QOS2
template <class Network, class Timer, int a, int b>
bool MQTT::Client<Network, Timer, a, b>::isQoS2msgidFree(unsigned short id) {
  for (int i = 0; i < MAX_INCOMING_QOS2_MESSAGES; ++i) {
    if (incomingQoS2messages[i] == id) return false;
  }
  return true;
}

template <class Network, class Timer, int a, int b>
bool MQTT::Client<Network, Timer, a, b>::useQoS2msgid(unsigned short id) {
  for (int i = 0; i < MAX_INCOMING_QOS2_MESSAGES; ++i) {
    if (incomingQoS2messages[i] == 0) {
      incomingQoS2messages[i] = id;
      return true;
    }
  }
  return false;
}

template <class Network, class Timer, int a, int b>
void MQTT::Client<Network, Timer, a, b>::freeQoS2msgid(unsigned short id) {
  for (int i = 0; i < MAX_INCOMING_QOS2_MESSAGES; ++i) {
    if (incomingQoS2messages[i] == id) {
      incomingQoS2messages[i] = 0;
      return;
    }
  }
}
#endif
}  // namespace MQTT
