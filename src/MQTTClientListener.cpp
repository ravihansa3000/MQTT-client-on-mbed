#include "MQTTClient.h"

namespace MQTT {

int MQTTClient::cycle() {
  int rc;

  if (!_is_connected) {
    if (_use_tls) {
      init_tls();
    }

    if ((rc = connect()) < 0) {
      if (rc == NSAPI_ERROR_PARAMETER || rc == NSAPI_ERROR_NO_SOCKET || rc == NSAPI_ERROR_NO_MEMORY ||
          rc == NSAPI_ERROR_DHCP_FAILURE || rc == NSAPI_ERROR_DNS_FAILURE || rc == NSAPI_ERROR_DEVICE_ERROR) {
        ERR("Network error occurred while connecting to MQTT broker (error code: %d) ... [FAIL]", rc);
        return NETWORK_ERROR;
      } else {
        ERR("Failed to establish MQTT connection (error code: %d) ... [FAIL]", rc);
        return MQTT_ERROR;
      }
    }

    if ((rc = process_subscriptions()) == SUCCESS) {  // subscribe to MQTT topics in registered message handlers
      INFO("Successfully processed topic subscriptions ... [OK]");
    } else {
      ERR("Failed to process topic subscriptions (error code: %d), MQTT client will disconnect ... [FAIL]", rc);
      disconnect();
      return MQTT_ERROR;
    }
  }

  int type = read_packet();
  switch (type) {
    case TIMEOUT:  // No data available from the network
      break;

    case NSAPI_ERROR_PARAMETER:
    case NSAPI_ERROR_NO_SOCKET:
    case NSAPI_ERROR_NO_MEMORY:
    case NSAPI_ERROR_DHCP_FAILURE:
    case NSAPI_ERROR_DNS_FAILURE:
    case NSAPI_ERROR_DEVICE_ERROR:
    case NSAPI_ERROR_NO_CONNECTION: {
      ERR("Network error detected (error code: %d), MQTT client will disconnect ... [FAIL]", type);
      disconnect();
      return NETWORK_ERROR;
    }

    case 0:  // MQTT broker has closed the connection
    case FAILURE: {
      ERR("Server error detected while reading packet (error code: %d), MQTT client will disconnect ... [FAIL]", type);
      disconnect();
      return MQTT_ERROR;
    }

    case BUFFER_OVERFLOW: {
      ERR("Buffer overflow detected while reading packet, MQTT client will disconnect ... [FAIL]");
      disconnect();
      return BUFFER_OVERFLOW;
    }

    case CONNACK:
    case PUBACK:
    case SUBACK:
      break;

    case PUBLISH: {  // received data from the MQTT broker
      if ((rc = handle_publish_message()) < 0) {
        ERR("Error handling PUBLISH message received (error code: %d), MQTT client will disconnect ... [FAIL]", rc);
        disconnect();
        return MQTT_ERROR;
      }
      break;
    }

    case PINGRESP: {
      DBG("Got ping response.");
      reset_connection_timer();
      break;
    }

    default: {
      ERR("Unknown packet type from MQTT broker. [type] %d", type);
      if (type < 0) {  // unhandled protocol error
        ERR("Unhandled protocol error, MQTT client will disconnect ... [FAIL]");
        disconnect();
        return MQTT_ERROR;
      }
    }
  }
  mqtt_health_check();
  DBG("MQTT listener read packet end");

  return SUCCESS;
}
}  // namespace MQTT
