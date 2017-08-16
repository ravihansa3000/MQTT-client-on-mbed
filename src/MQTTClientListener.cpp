#include "MQTTClient.h"

namespace MQTT {
void MQTTClient::start_listener() {
  if (!_initialized) {
    ERR("MQTT client has not been initialized, MQTT client listener will exit ... [FAIL]");
    return;
  }
  if (_use_tls) {
    init_tls();
  }
  INFO("MQTT client listener started ... [OK]");
  while (_is_running) {  // connect loop
    int rc = 0;
    if ((rc = connect()) < 0) {
      disconnect();
      if (rc == NSAPI_ERROR_PARAMETER || rc == NSAPI_ERROR_NO_SOCKET || rc == NSAPI_ERROR_NO_MEMORY ||
          rc == NSAPI_ERROR_DEVICE_ERROR) {  // unrecoverable error
        ERR("Unrecoverable network error detected (error code: %d), MQTT client listener will exit ... [FAIL]", rc);
        return;
      } else {
        ERR("Failed to establish MQTT connection (error code: %d), try again in %d seconds ... [FAIL]", rc,
            (MQTT_RECONNECT_TIMEOUT / 1000));
        Thread::wait(MQTT_RECONNECT_TIMEOUT);
        continue;
      }
    }

    if ((rc = process_subscriptions()) == SUCCESS) {
      INFO("Successfully processed topic subscriptions ... [OK]");
    } else {
      ERR("Failed to process topic subscriptions (error code: %d), try again in %d seconds ... [FAIL]", rc,
          (MQTT_RECONNECT_TIMEOUT / 1000));
      continue;
    }

    while (_is_running && _is_connected) {  // read loop
      int type = read_packet();
      switch (type) {
        case TIMEOUT:  // No data available from the network
          break;

        case NSAPI_ERROR_PARAMETER:
        case NSAPI_ERROR_NO_SOCKET:
        case NSAPI_ERROR_NO_MEMORY:
        case NSAPI_ERROR_DEVICE_ERROR: {
          ERR("Unrecoverable network error detected (error code: %d), MQTT client listener is exiting ... [FAIL]",
              type);
          return;
        } break;

        case 0:                          // server has closed the connection
        case NSAPI_ERROR_NO_CONNECTION:  // connection has failed
        case FAILURE: {
          ERR("Error while reading packet (error code: %d), disconnecting ... [FAIL]", type);
          disconnect();
        } break;

        case BUFFER_OVERFLOW: {
          ERR("Failure or buffer overflow detected, disconnecting ... [FAIL]");
          disconnect();
        } break;

        case CONNACK:
        case PUBACK:
        case SUBACK:
          break;

        case PUBLISH: {  // received data from the MQTT server
          if ((rc = handle_publish_message()) < 0) {
            ERR("Error handling PUBLISH message received (error code: %d) ... [FAIL]", rc);
          }
        } break;

        case PINGRESP: {
          DBG("Got ping response...");
          reset_connection_timer();
        } break;

        default: {
          ERR("Unknown packet type from server. [type] %d", type);
          if (type < 0) {  // unhandled network error
            ERR("Unhandled network error, disconnecting ... [FAIL]");
            disconnect();
          }
        }
      }

      if (_is_connected && _is_running) {
        if ((rc = has_connection_timed_out()) != 0) {  // check if its time to send a keepAlive packet
          if (rc == -1 && _ping_request_sent == false) {
            DBG("MQTT keep alive expired, sending ping request...");
            _equeue.call(this, &MQTTClient::send_ping_request);
          } else if (rc == -2) {
            ERR("MQTT server is unresponsive, disconnecting ... [FAIL]");
            disconnect();
          }
        }
      }

    }  // end read loop
  }    // end connect loop
}

void MQTTClient::stop_listener() {
  _is_running = false;
  disconnect();
}
}
