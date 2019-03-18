#include "MQTTClient.h"

namespace MQTT {
int MQTTClient::send_bytes_from_buffer(char *buffer, size_t size) {
  int rc;
  if (_use_tls) {  // Do SSL/TLS write
    rc = mbedtls_ssl_write(&_ssl, (const unsigned char *)buffer, size);
    if (MBEDTLS_ERR_SSL_WANT_WRITE == rc) {
      return TIMEOUT;
    } else {
      DBG("TLS socket write: [rc] %d", rc);
      return rc;
    }
  } else {
    rc = _tcpsocket.send(buffer, size);
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
  if (_use_tls) {  // Do SSL/TLS read
    rc = mbedtls_ssl_read(&_ssl, (unsigned char *)buffer, size);
    if (MBEDTLS_ERR_SSL_WANT_READ == rc) {
      return TIMEOUT;
    } else {
      DBG("TLS socket read: [rc] %d", rc);
      return rc;
    }
  } else {
    rc = _tcpsocket.recv((void *)buffer, size);
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
}