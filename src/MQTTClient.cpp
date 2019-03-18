#include "MQTTClient.h"

namespace MQTT {
const char *MQTTClient::DRBG_PERS = "mbed TLS MQTT client";

MQTTClient::MQTTClient(RtosLogger *logger, NetworkInterface *net, bool use_tls, bool ssl_cert_verify, const char *pem)
    : _is_connected(false),
      _ssl_initialized(false),
      _has_saved_session(false),
      _ping_request_sent(false),
      _logger(logger),
      _network(net),
      _equeue(MQTT_PUBLISH_EVENT_QUEUE_SIZE * EVENTS_MQTT_PUBLISH_EVENT_SIZE, NULL),
      _use_tls(use_tls),
      _ssl_cert_verify(ssl_cert_verify),
      _ssl_ca_pem(pem),
      _port(0),
      _sendbuf{0},
      _readbuf{0},
      _keepalive_interval(0),
      _message_handlers{0},
      _publishbuf() {}

MQTTClient::~MQTTClient() {
  disconnect();
  free_tls();
}

int MQTTClient::connect() {
  int rc;
  if (_network == NULL || _host.empty()) {
    ERR("MQTT settings not set ... [FAIL]");
    return FAILURE;
  }

  if (_is_connected) {
    WARN("MQTT client is already connected!");
    return INVALID;
  }

  if (_use_tls) {
    if ((rc = mbedtls_ssl_session_reset(&_ssl)) != 0) {
      ERR("mbedtls_ssl_session_reset failed (error code: %d) ... [FAIL]", rc);
      free_tls();
      return FAILURE;
    }

#if defined(MBEDTLS_SSL_CLI_C)
    if (_has_saved_session && ((rc = mbedtls_ssl_set_session(&_ssl, &_ssl_saved_session)) != 0)) {
      _has_saved_session = false;
      ERR("mbedtls_ssl_set_session failed (error code: %d) ... [FAIL]", rc);
      free_tls();
      return FAILURE;
    }
#endif

    DBG("mbedtls_ssl_set_hostname...");
    mbedtls_ssl_set_hostname(&_ssl, _host.c_str());
    DBG("mbedtls_ssl_set_bio...");
    mbedtls_ssl_set_bio(&_ssl, static_cast<MQTTClient *>(this), ssl_send, ssl_recv, NULL);
  }

  INFO("Connecting to MQTT broker [host] %s, [port] %d ...", _host.c_str(), _port);
  _tcpsocket.open(_network);
  _tcpsocket.set_timeout(MQTT_SOCKET_TIMEOUT);

  if ((rc = _tcpsocket.connect(_host.c_str(), _port)) < 0) {
    ERR("Could not connect to MQTT broker [host] %s, [port] %d, [rc] %d", _host.c_str(), _port, rc);
    _tcpsocket.close();
    return rc;  // return network error
  } else {
    INFO("Socket connected [host] %s, [port] %d, [rc] %d", _host.c_str(), _port, rc);
  }

  if (_use_tls) {
    if ((rc = do_tls_handshake()) < 0) {
      ERR("TLS handshake failed (error code: %d) ... [FAIL]", rc);
      return FAILURE;
    } else {
      INFO("TLS handshake successful ... [OK]");
    }
  }

  // authenticate and wait for connection acknowledgement
  rc = login();
  return rc;
}

int MQTTClient::login() {
  int rc;
  int len = 0;

  /**
   * Copy the _keepalive_interval value to local MQTT specifies in seconds, we have to multiply that
   * amount for our 32 bit timers which accepts ms.
   **/
  _keepalive_interval = (unsigned short)(_connect_options.keepAliveInterval * 1000);
  DBG("Authenticating with MQTT credentials. [username] %s, [password] *****", _connect_options.username.cstring);

  if ((len = MQTTSerialize_connect(_sendbuf, MAX_MQTT_PACKET_SIZE, &_connect_options)) <= 0) {
    ERR("Error serializing connect packet (error code: %d) ... [FAIL]", len);
    return FAILURE;
  }

  rc = send_packet((size_t)len);

  if (rc != SUCCESS) {  // send the connect packet
    ERR("Error sending the connect request packet (error code: %d) ... [FAIL]", rc);
    return FAILURE;
  }

  // Wait for the CONNACK
  unsigned char connack_rc = 255;
  rc = read_until(CONNACK, MQTT_COMMAND_TIMEOUT);
  if (rc == CONNACK) {
    bool sessionPresent = false;
    DBG("Connection acknowledgement received, deserializing response...");
    if ((rc = MQTTDeserialize_connack((unsigned char *)&sessionPresent, &connack_rc, _readbuf, MAX_MQTT_PACKET_SIZE)) ==
        1) {
      rc = connack_rc;
    } else {
      ERR("Error deserializing the connect acknowledgement packet (error code %d) ... [FAIL]", rc);
      rc = FAILURE;
    }
  } else {
    ERR("Error while waiting for connection acknowledgement ... [FAIL]", rc);
    rc = FAILURE;
  }

  if (rc == CONNACK_RC::ACCEPTED) {
    reset_connection_timer();  // reset connection timers for the new MQTT session
    _is_connected = true;
    INFO("MQTT connection established, starting connection timers ... [OK]");
    return SUCCESS;
  } else {
    ERR("MQTT connect CONNACK error (error code: %d) ... [FAIL]", rc);
    return FAILURE;
  }
}

int MQTTClient::disconnect() {
  if (!_is_connected) {
    WARN("MQTT client is already disconnected.");
    return INVALID;
  }

  DBG("MQTT client disconnecting...");
  int rc = FAILURE;
  int len = MQTTSerialize_disconnect(_sendbuf, MAX_MQTT_PACKET_SIZE);
  if (len > 0) {
    rc = send_packet(len);  // send the disconnect packet
  }

  // close the TCP socket and cleanup allocated resources
  _tcpsocket.close();

  if (_connect_options.cleansession) {
    clean_session();
  }

  _is_connected = false;
  INFO("MQTT client disconnected.");
  return rc;
}

int MQTTClient::publish(const char *topic, const char *payload, MQTT::QoS qos, bool retained, bool dup) {
  int topiclen = strlen(topic);
  if (strlen(topic) > MAX_MQTT_TOPIC_SIZE) {
    ERR("Could not publish MQTT message, topic length exceeds max limit: [len] %d, [max] %d", topiclen,
        MAX_MQTT_TOPIC_SIZE);
    return BUFFER_OVERFLOW;
  }
  int payloadlen = strlen(payload);
  if (payloadlen > MAX_MQTT_PAYLOAD_SIZE) {
    ERR("Could not publish MQTT message, payload length exceeds max limit: [len] %d, [max] %d", payloadlen,
        MAX_MQTT_PAYLOAD_SIZE);
    return BUFFER_OVERFLOW;
  }
  if (qos != QOS0) {  // TODO: only QoS0 is supported for now
    ERR("Could not publish MQTT message, unsupported QoS: [topic] %s, [payload] %s, [QoS] %d", topic, payload, qos);
    return FAILURE;
  }

  MQTTString mqtt_topic = MQTTString_initializer;
  _lock.lock();

  if (!_is_connected) {
    _lock.unlock();
    ERR("Could not publish MQTT message [topic] %s, not connected ... [FAIL]", topic);
    return FAILURE;
  }

  int id = _packetid.get_next();
  mqtt_topic.cstring = (char *)topic;
  int len = MQTTSerialize_publish(_sendbuf, MAX_MQTT_PACKET_SIZE, dup, qos, retained, id, mqtt_topic,
                                  (unsigned char *)payload, payloadlen);
  if (len <= 0) {
    _lock.unlock();
    ERR("Failed serializing publish message (error code: %d) ... [FAIL]", len);
    return MQTT_ERROR;
  }
  int rc = send_packet(len);
  _lock.unlock();

  if (rc == SUCCESS) {
    // reset_connection_timer(); // reset timers if we have been able to send successfully
    // TODO: troubleshoot mbedOS bug: send packet returns success although connection is broken
    DBG("Successfully published MQTT message, [topic] %s, [payload] %s, [qos] %d", topic, payload, qos);
    return SUCCESS;
  } else {
    ERR("Could not send MQTT message (error code: %d) ... [FAIL]", rc);
    return NETWORK_ERROR;
  }
}

int MQTTClient::post_publish(const char *topic, const char *payload, MQTT::QoS qos, bool retained, bool dup) {
  int topiclen = strlen(topic);
  if (strlen(topic) > MAX_MQTT_TOPIC_SIZE) {
    ERR("Could not publish MQTT message, topic length exceeds max limit: [len] %d, [max] %d", topiclen,
        MAX_MQTT_TOPIC_SIZE);
    return BUFFER_OVERFLOW;
  }
  size_t payloadlen = strlen(payload);
  if (payloadlen > MAX_MQTT_PAYLOAD_SIZE) {
    ERR("Could not publish MQTT message, payload length exceeds max limit: [len] %d, [max] %d", payloadlen,
        MAX_MQTT_PAYLOAD_SIZE);
    return BUFFER_OVERFLOW;
  }
  if (qos != QOS0) {  // TODO: only QoS0 is supported for now
    ERR("Could not publish MQTT message, unsupported QoS: [topic] %s, [payload] %s, [QoS] %d", topic, payload, qos);
    return FAILURE;
  }

  int i = 0;
  _lock.lock();

  if (!_is_connected) {
    _lock.unlock();
    ERR("Could not publish MQTT message [topic] %s, not connected ... [FAIL]", topic);
    return FAILURE;
  }

  while (i < MAX_MQTT_PUBLISH_MESSAGES) {
    if (_publishbuf[i].pub_message.id == 0) {
      break;
    }
    i++;
  }
  if (i >= MAX_MQTT_PUBLISH_MESSAGES) {
    _lock.unlock();
    ERR("Could not add to MQTT publish queue [topic] %s, publish buffer is full ... [FAIL]", topic);
    return BUFFER_FULL;
  }
  _publishbuf[i].pub_message.id = _packetid.get_next();
  _publishbuf[i].pub_message.qos = qos;
  _publishbuf[i].pub_message.retained = retained;
  _publishbuf[i].pub_message.dup = dup;
  _publishbuf[i].pub_message.payloadlen = payloadlen;
  snprintf(_publishbuf[i].pub_message.topic, sizeof(MQTTMessage::topic), "%s", topic);
  snprintf(_publishbuf[i].pub_message.payload, sizeof(MQTTMessage::payload), "%s", payload);
  _publishbuf[i].pub_timer.reset();
  _publishbuf[i].pub_timer.start();

  int rc = _equeue.call(callback(this, &MQTTClient::post_publish_callback), i);
  if (rc == 0) {
    _publishbuf[i].pub_message.id = 0;
    _lock.unlock();
    ERR("Could not add to MQTT publish queue [topic] %s, event queue is full ... [FAIL]", topic);
    return BUFFER_FULL;
  } else {
    _lock.unlock();
    return SUCCESS;
  }
}

void MQTTClient::post_publish_callback(int index) {
  if (index < 0 || index >= MAX_MQTT_PUBLISH_MESSAGES) {
    ERR("Could not send queued MQTT message, invalid index: %d ... [FAIL]", index);
    return;
  }

  if (_publishbuf[index].pub_message.id == 0) {
    return;
  }

  MQTTString mqtt_topic = MQTTString_initializer;
  _lock.lock();

  if (!_is_connected) {
    _lock.unlock();
    ERR("Could not send queued MQTT message, not connected ... [FAIL]");
    return;
  }

  if (_publishbuf[index].pub_timer.read_ms() > MQTT_PUBLISH_TIMEOUT) {
    _publishbuf[index].pub_message.id = 0;  // mark publish message buffer space as free
    _publishbuf[index].pub_timer.stop();
    _publishbuf[index].pub_timer.reset();
    _lock.unlock();
    ERR("Could not send queued MQTT message, timeout expired ... [FAIL]");
    return;
  }

  mqtt_topic.cstring = (char *)&_publishbuf[index].pub_message.topic[0];
  int len = MQTTSerialize_publish(_sendbuf, MAX_MQTT_PACKET_SIZE, 0, _publishbuf[index].pub_message.qos, false,
                                  _publishbuf[index].pub_message.id, mqtt_topic,
                                  (unsigned char *)&_publishbuf[index].pub_message.payload[0],
                                  (int)_publishbuf[index].pub_message.payloadlen);

  if (len <= 0) {
    _publishbuf[index].pub_message.id = 0;  // mark publish message buffer space as free
    _publishbuf[index].pub_timer.stop();
    _publishbuf[index].pub_timer.reset();
    _lock.unlock();
    ERR("Failed to serialize publish message (error code: %d) ... [FAIL]", len);
    return;
  }

  int rc = send_packet(len);
  _publishbuf[index].pub_message.id = 0;  // mark publish message buffer space as free
  _publishbuf[index].pub_timer.stop();
  _publishbuf[index].pub_timer.reset();
  _lock.unlock();

  if (rc == SUCCESS) {
    // reset_connection_timer(); // reset timers if we have been able to send successfully
    // TODO: troubleshoot mbedOS bug: send packet returns success although connection is broken
    DBG("Successfully published MQTT message, [topic] %s, [payload] %s, [qos] %d", _publishbuf[index].pub_message.topic,
        _publishbuf[index].pub_message.payload, _publishbuf[index].pub_message.qos);
  } else {
    ERR("Could not send MQTT message (error code: %d) ... [FAIL]", rc);
  }
}

void MQTTClient::set_connection_parameters(const char *host, uint16_t port, MQTTPacket_connectData &options) {
  _host = host;
  _port = port;
  _connect_options = options;
}

int MQTTClient::set_message_handler(const char *topic, Callback<void(MQTTMessage &)> cb) {
  int rc = FAILURE;
  int i = -1;
  for (i = 0; i < MAX_MQTT_MESSAGE_HANDLERS; ++i) {  // first check for an existing matching slot
    if (_message_handlers[i].topic_filter != 0 && strcmp(_message_handlers[i].topic_filter, topic) == 0) {
      if (cb) {  // replace existing
        _message_handlers[i].topic_cb = cb;
      } else {  // remove existing
        _message_handlers[i].topic_filter = 0;
        _message_handlers[i].topic_cb = 0;
      }
      rc = SUCCESS;  // return i when adding new subscription
      break;
    }
  }

  if (cb) {  // if no existing, look for empty slot (unless we are removing)
    if (rc == FAILURE) {
      for (i = 0; i < MAX_MQTT_MESSAGE_HANDLERS; ++i) {
        if (_message_handlers[i].topic_filter == 0) {
          rc = SUCCESS;
          break;
        }
      }
    }
    if (i < MAX_MQTT_MESSAGE_HANDLERS) {
      _message_handlers[i].topic_filter = topic;
      _message_handlers[i].topic_cb = cb;
    }
  }
  return rc;
}

EventQueue &MQTTClient::equeue() { return _equeue; }

bool MQTTClient::is_connected() { return _is_connected; }

}  // namespace MQTT
