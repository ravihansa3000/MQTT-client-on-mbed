#include "MQTTClient.h"

namespace MQTT {

/**
* Receive callback for mbed TLS
*/
int MQTTClient::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
  MQTTClient *client = static_cast<MQTTClient *>(ctx);
  client->_tcpsocket.set_timeout(MQTT_SOCKET_TIMEOUT);
  int recv = client->_tcpsocket.recv(buf, len);

  if (NSAPI_ERROR_WOULD_BLOCK == recv) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  } else if (recv < 0) {
    client->_logger->atprintf("[ERROR][MQTTClient] Failed to receive SSL data. [rc] %d ... [FAIL] \r\n", recv);
    return FAILURE;
  } else {
    return recv;
  }
}

/**
* Send callback for mbed TLS
*/
int MQTTClient::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
  MQTTClient *client = static_cast<MQTTClient *>(ctx);
  client->_tcpsocket.set_timeout(MQTT_SOCKET_TIMEOUT);
  int sent = client->_tcpsocket.send(buf, len);

  if (NSAPI_ERROR_WOULD_BLOCK == sent) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  } else if (sent < 0) {
    client->_logger->atprintf("[ERROR][MQTTClient] Failed to send SSL data. [rc] %d ... [FAIL] \r\n", sent);
    return FAILURE;
  } else {
    return sent;
  }
}

#if DEBUG_LEVEL > 0
/**
* Debug callback for mbed TLS
* Just prints on the USB serial port
*/
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  const char *p, *basename;
  RtosLogger *logger = static_cast<RtosLogger *>(ctx);

  /* Extract basename from file */
  for (p = basename = file; *p != '\0'; p++) {
    if (*p == '/' || *p == '\\') {
      basename = p + 1;
    }
  }
  logger->atprintf("[DEBUG][MQTTClient] %s:%04d: |%d| %s", basename, line, level, str);
}

/**
* Certificate verification callback for mbed TLS
* Here we only use it to display information on each cert in the chain
*/
static int my_verify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
  char *buf = new char[MQTT_CRT_BUFFER_SIZE];
  RtosLogger *logger = static_cast<RtosLogger *>(ctx);

  logger->atprintf("[DEBUG][MQTTClient] Verifying certificate. [depth] %d \r\n", depth);
  mbedtls_x509_crt_info(buf, MQTT_CRT_BUFFER_SIZE - 1, "  ", crt);
  logger->atprintf("[DEBUG][MQTTClient] Certificate info: \r\n%s \r\n", buf);

  if (*flags == 0) {
    logger->atprintf("[DEBUG][MQTTClient] No verification issue for this certificate. \r\n");
  } else {
    mbedtls_x509_crt_verify_info(buf, MQTT_CRT_BUFFER_SIZE, "  ! ", *flags);
    logger->atprintf("[DEBUG][MQTTClient] Certificate verify info: \r\n%s \r\n", buf);
  }
  delete[] buf;
  return 0;
}
#endif

int MQTTClient::init_tls() {
  if (_ssl_initialized) {  // prevent memory leaks
    return -1;
  }

  INFO("Initializing SSL configuration context...");
  mbedtls_entropy_init(&_entropy);
  mbedtls_ctr_drbg_init(&_ctr_drbg);
  mbedtls_x509_crt_init(&_cacert);
  mbedtls_x509_crt_init(&_owncert);
  mbedtls_pk_init(&_pkctx);
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_ssl_conf);
  memset(&_ssl_saved_session, 0, sizeof(mbedtls_ssl_session));

  int rc;
  DBG("mbedtls_ctr_drbg_seed...");
  if ((rc = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, (const unsigned char *)DRBG_PERS,
                                  sizeof(DRBG_PERS))) != 0) {
    ERR("mbedtls_crt_drbg_init failed (error code %d) ... [FAIL]", rc);
    return rc;
  }

  DBG("mbedtls_x509_crt_parse: CA cert...");
  if ((rc = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *)_ssl_ca_pem, strlen(_ssl_ca_pem) + 1)) != 0) {
    ERR("mbedtls_x509_crt_parse: CA cert failed (error code %d) ... [FAIL]", rc);
    return rc;
  }
  DBG("mbedtls_x509_crt_parse: CA cert ... [OK]");

  DBG("mbedtls_x509_crt_parse: own cert...");
  if ((rc = mbedtls_x509_crt_parse(&_owncert, (const unsigned char *)SSL_OWN_CERT_PEM, strlen(SSL_OWN_CERT_PEM) + 1)) !=
      0) {
    ERR("mbedtls_x509_crt_parse: own cert failed (error code %d) ... [FAIL]", rc);
    return rc;
  }
  DBG("mbedtls_x509_crt_parse: own cert ... [OK]");

  DBG("mbedtls_pk_parse_key: own key...");
  if ((rc = mbedtls_pk_parse_key(&_pkctx, (const unsigned char *)SSL_OWN_KEY_PEM, strlen(SSL_OWN_KEY_PEM) + 1, NULL,
                                 0)) != 0) {
    ERR("mbedtls_pk_parse_key failed (error code %d) ... [FAIL]", rc);
    return rc;
  }
  DBG("mbedtls_pk_parse_key: own key ... [OK]");

  DBG("mbedtls_ssl_config_defaults...");
  if ((rc = mbedtls_ssl_config_defaults(&_ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    ERR("mbedtls_ssl_config_defaults failed (error code %d) ... [FAIL]", rc);
    return rc;
  }

  DBG("mbedtls_ssl_config_ca_chain...");
  mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);

  DBG("mbedtls_ssl_conf_own_cert...");
  mbedtls_ssl_conf_own_cert(&_ssl_conf, &_owncert, &_pkctx);

  DBG("mbedtls_ssl_conf_rng...");
  mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

  /**
  * It is possible to disable authentication by passing
  * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
  **/
  DBG("mbedtls_ssl_conf_authmode, ssl_cert_verify: %s", (_ssl_cert_verify ? "true" : "false"));
  if (_ssl_cert_verify) {
    mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  } else {
    mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  }

#if DEBUG_LEVEL > 0
  mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, static_cast<RtosLogger *>(_logger));
  mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, static_cast<RtosLogger *>(_logger));
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

  if ((rc = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
    ERR("mbedtls_ssl_setup failed (error code %d) ... [FAIL]", rc);
    return rc;
  }

  _ssl_initialized = true;
  return 0;
}

void MQTTClient::free_tls() {
  if (_ssl_initialized) {  // prevent calling 'free' on uninitialized pointers
    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);
    mbedtls_x509_crt_free(&_cacert);
    mbedtls_x509_crt_free(&_owncert);
    mbedtls_pk_free(&_pkctx);
    mbedtls_ssl_free(&_ssl);
    mbedtls_ssl_config_free(&_ssl_conf);
    _ssl_initialized = false;
    INFO("SSL configuration context cleared.");
  } else {
    WARN("SSL configuration context is already cleared.");
  }
}

int MQTTClient::do_tls_handshake() {
  INFO("Starting TLS handshake...");
  int rc = FAILURE;
  int retry_count = 0;
  do {
    rc = mbedtls_ssl_handshake(&_ssl);
    retry_count++;
    DBG("TLS handshake result [rc] %d, [count] %d", rc, retry_count);
  } while (rc != 0 && (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) && retry_count < 3);

  if (rc < 0) {
    ERR("mbedtls_ssl_handshake failed (error code %d) ... [FAIL]", rc);
    return rc;
  }

  // Handshake done, time to print info
  INFO("TLS connection to %s:%d established ... [OK]", _host.c_str(), _port);
  char *buf = new char[MQTT_CRT_BUFFER_SIZE];
  mbedtls_x509_crt_info(buf, MQTT_CRT_BUFFER_SIZE, "\r    ", mbedtls_ssl_get_peer_cert(&_ssl));
  DBG("Server certificate:\r\n%s", buf);
  uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);  // Verify server cert
  if (flags != 0) {
    mbedtls_x509_crt_verify_info(buf, MQTT_CRT_BUFFER_SIZE, "\r  ! ", flags);
    ERR("Certificate verification failed:\r\n%s", buf);
    delete[] buf;  // Free server cert ... before error return
    return FAILURE;
  }

  DBG("Certificate verification passed");
  // Delete server cert after verification
  delete[] buf;

#if defined(MBEDTLS_SSL_CLI_C)
  DBG("Saving SSL/TLS session...");
  if ((rc = mbedtls_ssl_get_session(&_ssl, &_ssl_saved_session)) != 0) {
    _has_saved_session = false;
    ERR("mbedtls_ssl_get_session failed. [rc] %d", rc);
    return rc;
  } else {
    _has_saved_session = true;
  }
#endif

  return SUCCESS;
}
}
