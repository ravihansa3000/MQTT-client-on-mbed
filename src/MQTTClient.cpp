#include "MQTTClient.h"

namespace MQTT {

MQTTClient::MQTTClient(RtosLogger *logger, NetworkInterface *net, bool use_tls, bool ssl_cert_verify, const char *pem)
    : _logger(logger),
      _network(net),
      _initialized(false),
      _use_tls(use_tls),
      _ssl_cert_verify(ssl_cert_verify),
      _ssl_ca_pem(pem),
      _port(use_tls ? 8883 : 1883),
      _equeue(MQTT_EVENT_QUEUE_SIZE * EVENTS_EVENT_SIZE),
      _is_connected(false),
      _is_running(false),
      _has_saved_session(false),
      _ping_request_sent(false),
      _mqtt_ticker(),
      _lock(),
      _publisher_thread(osPriorityNormal, PUBLISHER_STACK_SIZE, NULL, "MQTT_Publisher") {}

MQTTClient::~MQTTClient() {
  _is_running = false;  // break the MQTT client listener loop
  free_tls();
  if (_is_connected) {
    disconnect();
  }
  delete _tcpsocket;
  _equeue.break_dispatch();
}

int MQTTClient::init() {
  MQTTClientError err = Ok;
  if (!_initialized) {
    do {
      DRBG_PERS = "mbed TLS MQTT client";
      _tcpsocket = new TCPSocket();
      if (_tcpsocket == NULL) {
        ERR("Failed to create TCP socket ... [FAIL]");
        err = TCPSocketError;
        break;
      }
      setup_tls();

      _is_running = true;
      osStatus status = _publisher_thread.start(callback(this, &MQTTClient::mqtt_publisher_task));
      if (status != osOK) {
        ERR("Failed to start MQTT publisher thread ... [FAIL]");
        err = PublisherError;
        _is_running = false;
        break;
      }
      _initialized = true;
      INFO("Initialized MQTT client [TLS] %s", (_use_tls == true ? "true" : "false"));
    } while (0);
  }

  return err;
}

void MQTTClient::mqtt_publisher_task() {
  osThreadId threadId = osThreadGetId();
  INFO("MQTT publisher task thread (TID: %p) started with a stack size of %d ... [OK]", threadId, PUBLISHER_STACK_SIZE);
  _mqtt_ticker.attach(_equeue.event(callback(this, &MQTTClient::mqtt_health_check)), MQTT_HEALTH_CHECK_INTERVAL);
  _equeue.dispatch_forever();  // dispatch messages queued to be published
  INFO("MQTT publisher task finished.");
}

int MQTTClient::send_bytes_from_buffer(char *buffer, size_t size) {
  int rc;
  if (_tcpsocket == NULL) {
    ERR("TCP socket not initialized ... [FAIL]");
    return -1;
  }

  if (_use_tls) {  // Do SSL/TLS write
    rc = mbedtls_ssl_write(&_ssl, (const unsigned char *)buffer, size);
    if (MBEDTLS_ERR_SSL_WANT_WRITE == rc) {
      return TIMEOUT;
    } else {
      DBG("TLS socket write: [rc] %d", rc);
      return rc;
    }
  } else {
    rc = _tcpsocket->send(buffer, size);
    if (NSAPI_ERROR_WOULD_BLOCK == rc) {
      return TIMEOUT;
    } else {
      DBG("socket write: [rc] %d", rc);
      return rc;
    }
  }
}

int MQTTClient::read_packet_length(int *value) {
  int rc = MQTTPACKET_READ_ERROR;
  unsigned char c;
  int multiplier = 1;
  int len = 0;
  const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

  *value = 0;
  do {
    if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
      rc = MQTTPACKET_READ_ERROR; /* bad data */
      goto exit;
    }

    rc = read_bytes_to_buffer((char *)&c, 1);
    if (rc != 1) {
      rc = MQTTPACKET_READ_ERROR;
      goto exit;
    }

    *value += (c & 127) * multiplier;
    multiplier *= 128;
  } while ((c & 128) != 0);

  rc = MQTTPACKET_READ_COMPLETE;

exit:
  if (rc == MQTTPACKET_READ_ERROR) {
    len = -1;
  }
  DBG("Packet length: %d", len);
  return len;
}

int MQTTClient::send_packet(size_t length) {
  int rc = FAILURE;
  unsigned int sent = 0;

  while (sent < length) {
    rc = send_bytes_from_buffer((char *)&_sendbuf[sent], length - sent);
    if (rc < 0) {  // there was an error writing the data
      ERR("Failed to send data (error code: %d) ... [FAIL]", rc);
      break;
    }
    sent += rc;
  }

  if (sent == length) {
    rc = SUCCESS;
  } else {
    rc = FAILURE;
    ERR("Failed to send packet, sent %d of %d bytes ... [FAIL]", sent, length);
  }
  return rc;
}

int MQTTClient::read_bytes_to_buffer(char *buffer, size_t size) {
  int rc;
  if (_tcpsocket == NULL) {
    ERR("TCP socket not initialized ... [FAIL]");
    return -1;
  }
  if (_use_tls) {  // Do SSL/TLS read
    rc = mbedtls_ssl_read(&_ssl, (unsigned char *)buffer, size);
    if (MBEDTLS_ERR_SSL_WANT_READ == rc) {
      return TIMEOUT;
    } else {
      DBG("TLS socket read: [rc] %d", rc);
      return rc;
    }
  } else {
    rc = _tcpsocket->recv((void *)buffer, size);
    if (NSAPI_ERROR_WOULD_BLOCK == rc) {
      return TIMEOUT;
    } else {
      DBG("socket read: [rc] %d", rc);
      return rc;  // return the number of bytes received or error
    }
  }
}

/**
* Reads the entire packet to readbuf and returns the type of packet when successful, otherwise
* a negative error code is returned.
**/
int MQTTClient::read_packet() {
  int rc = FAILURE;
  MQTTHeader header = {0};
  int len = 0;
  int rem_len = 0;

  // 1. Read the header byte.  This has the packet type in it.
  if ((rc = read_bytes_to_buffer((char *)&_readbuf[0], 1)) != 1) {
    if (rc == TIMEOUT) {  // data is not available yet
      goto exit;
    }
    ERR("Failed to read packet header (error code: %d) ... [FAIL]", rc);
    goto exit;
  }

  // 2. Read the remaining length.  This is variable in itself
  len = 1;
  if ((rc = read_packet_length(&rem_len)) < 0) {
    ERR("Failed to read remaining length value (error code: %d) ... [FAIL]", rc);
    goto exit;
  }

  len += MQTTPacket_encode(_readbuf + 1, rem_len);  // put the original remaining length into the buffer

  if (rem_len > (MAX_MQTT_PACKET_SIZE - len)) {
    rc = BUFFER_OVERFLOW;
    ERR("Failed to read packet, buffer overflow detected ... [FAIL]");
    goto exit;
  }

  // 3. Read the rest of the buffer using a callback to supply the rest of the data
  if (rem_len > 0 && ((rc = read_bytes_to_buffer((char *)(_readbuf + len), rem_len)) != rem_len)) {
    ERR("Failed to read remaining data in packet (error code: %d) ... [FAIL]", rc);
    goto exit;
  }

  // Convert the header to type and update rc
  header.byte = _readbuf[0];
  rc = header.bits.type;

exit:
  return rc;
}

int MQTTClient::login() {
  int rc = FAILURE;
  int len = 0;

  if (!_is_connected) {
    ERR("Session not connected ... [FAIL]");
    return rc;
  }

  /**
  * Copy the _keepalive_interval value to local MQTT specifies in seconds, we have to multiply that
  * amount for our 32 bit timers which accepts ms.
  **/
  _keepalive_interval = (_connect_options.keepAliveInterval * 1000);
  DBG("Authenticating with MQTT credentials. [username] %s, [password] *****", _connect_options.username.cstring);
  _lock.lock();
  if ((len = MQTTSerialize_connect(_sendbuf, MAX_MQTT_PACKET_SIZE, &_connect_options)) <= 0) {
    ERR("Error serializing connect packet (error code: %d) ... [FAIL]", len);
    _lock.unlock();
    return rc;
  }
  rc = send_packet((size_t)len);
  _lock.unlock();
  if (rc != SUCCESS) {  // send the connect packet
    ERR("Error sending the connect request packet (error code: %d) ... [FAIL]", rc);
    return rc;
  }

  // Wait for the CONNACK
  unsigned char connack_rc = 255;
  rc = read_until(CONNACK, COMMAND_TIMEOUT);
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
  if (rc == SUCCESS) {
    INFO("MQTT connection established, starting connection timers ... [OK]");
    reset_connection_timer();  // reset connection timers for the new MQTT session
  }
  DBG("MQTT login returning with [rc] %d, [connack_rc] %d", rc, connack_rc);
  return rc;
}

void MQTTClient::disconnect() {
  int rc = 0;
  if (_use_tls && (rc = mbedtls_ssl_session_reset(&_ssl) != 0)) {
    ERR("mbedtls_ssl_session_reset failed (error code: %d) ... [FAIL]", rc);
  }
  _is_connected = false;
  _tcpsocket->close();
  INFO("MQTT client disconnected.");
}

int MQTTClient::connect() {
  int ret = FAILURE;
  if ((_network == NULL) || (_tcpsocket == NULL) || _host.empty()) {
    ERR("Network settings not set ... [FAIL]");
    return ret;
  }

  if (_use_tls) {
    if ((ret = mbedtls_ssl_session_reset(&_ssl)) != 0) {
      ERR("mbedtls_ssl_session_reset failed (error code: %d) ... [FAIL]", ret);
      return ret;
    }
#if defined(MBEDTLS_SSL_CLI_C)
    if (_has_saved_session && ((ret = mbedtls_ssl_set_session(&_ssl, &_ssl_saved_session)) != 0)) {
      ERR("mbedtls_ssl_conf_session failed (error code: %d) ... [FAIL]", ret);
      return ret;
    }
#endif
  }

  _tcpsocket->open(_network);
  _tcpsocket->set_timeout(DEFAULT_SOCKET_TIMEOUT);
  if (_use_tls) {
    DBG("mbedtls_ssl_set_hostname...");
    mbedtls_ssl_set_hostname(&_ssl, _host.c_str());
    DBG("mbedtls_ssl_set_bio...");
    mbedtls_ssl_set_bio(&_ssl, static_cast<MQTTClient *>(this), ssl_send, ssl_recv, NULL);
  }

  if ((ret = _tcpsocket->connect(_host.c_str(), _port)) < 0) {
    ERR("Error connecting to [host] %s, [port] %d, [rc] %d", _host.c_str(), _port, ret);
    return ret;
  } else {
    DBG("Successfully connected to MQTT server [host] %s, [port] %d, [rc] %d", _host.c_str(), _port, ret);
    _is_connected = true;
  }
  if (_use_tls) {
    if ((ret = do_tls_handshake()) < 0) {
      ERR("TLS handshake failed (error code: %d) ... [FAIL]", ret);
      return FAILURE;
    } else {
      INFO("TLS handshake successful ... [OK]");
    }
  }
  return login();
}
}
