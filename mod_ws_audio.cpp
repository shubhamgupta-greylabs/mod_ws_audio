/*
 * mod_ws_audio.cpp - WebSocket Audio Module for FreeSWITCH (C++)
 * 
 * APIs:
 * - ws_audio_start <ws host> <port> - Connect to WebSocket server on given host:port
 * - ws_audio_stop - Stop WebSocket server
 * 
 * WebSocket Protocol:
 * - Incoming audio from call (binary frames)
 * - Commands to play audio (JSON)
 * - Notifications when audio finishes (JSON)
 * - Support for interrupting playback
 */

#include <switch.h>
#include <libwebsockets.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <cjson/cJSON.h>
#include "websocket_handler.h"
#include "audio_session_handler.h"

extern "C" {
    SWITCH_MODULE_LOAD_FUNCTION(mod_ws_audio_load);
    SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_ws_audio_shutdown);
    SWITCH_MODULE_DEFINITION(mod_ws_audio, mod_ws_audio_load, mod_ws_audio_shutdown, NULL);
}

class WebSocketAudioModule;
class AudioSession;

extern "C" {

    // API to connect to webSocket server
    SWITCH_STANDARD_API(ws_audio_start_api) {
        char  *mycmd = NULL, *argv[6] = { 0 };

        int argc = 0;
        if (!zstr(cmd) && (mycmd = strdup(cmd))) {
            argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
        }
        
        if (!cmd || strlen(cmd) == 0) {
            stream->write_function(stream, "Usage: ws_audio_start <port>\n");
            return SWITCH_STATUS_SUCCESS;
        }
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                        "ws_audio_start command received: %s %d\n", cmd, argc);
        if (argc < 2) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                            "Invalid command provided\n");

            return SWITCH_STATUS_SUCCESS;
        }

        std::string host = argv[0];
        int port = std::stoi(argv[1]);

        if (port <= 0 || port > 65535) {
            stream->write_function(stream, "Invalid port number: %s\n", cmd);
            return SWITCH_STATUS_SUCCESS;
        }
        
        auto* module = WebSocketAudioModule::instance();
        if (!module) {
            stream->write_function(stream, "Module not initialized\n");
            return SWITCH_STATUS_SUCCESS;
        }
        
        if (module->is_server_running()) {
            stream->write_function(stream, "WebSocket server already running on port %d\n", 
                                module->get_server_port());
            return SWITCH_STATUS_SUCCESS;
        }
        
        bool success = module->connect_to_websocket_server(host, port);
        if (success) {
            stream->write_function(stream, "WebSocket server started on port %d\n", port);
        } else {
            stream->write_function(stream, "Failed to start WebSocket server on port %d\n", port);
        }
        
        return SWITCH_STATUS_SUCCESS;
    }

    // API to disconnect from webSocket server
    SWITCH_STANDARD_API(ws_audio_stop_api) {
        auto* module = WebSocketAudioModule::instance();
        if (!module) {
            stream->write_function(stream, "Module not initialized\n");
            return SWITCH_STATUS_SUCCESS;
        }
        
        if (!module->is_server_running()) {
            stream->write_function(stream, "WebSocket server is not running\n");
            return SWITCH_STATUS_SUCCESS;
        }
        
        bool success = module->disconnect_websocket_client();
        if (success) {
            stream->write_function(stream, "WebSocket server stopped\n");
        } else {
            stream->write_function(stream, "Failed to stop WebSocket server\n");
        }
        
        return SWITCH_STATUS_SUCCESS;
    }

    SWITCH_MODULE_LOAD_FUNCTION(mod_ws_audio_load) {
        switch_api_interface_t* api_interface;
        
        auto* module = WebSocketAudioModule::instance();
        
        if (!module->initialize(module_interface, pool)) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                            "Failed to initialize WebSocket Audio Module\n");
            return SWITCH_STATUS_GENERR;
        }
        
        // Connect internal structure to the blank pointer passed to us
        *module_interface = switch_loadable_module_create_module_interface(pool, modname);
        
        // Register APIs
        SWITCH_ADD_API(api_interface, "ws_audio_start", "Start WebSocket audio server", 
                    ws_audio_start_api, "ws_audio_start <port>");
        SWITCH_ADD_API(api_interface, "ws_audio_stop", "Stop WebSocket audio server", 
                    ws_audio_stop_api, "");
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                        "WebSocket Audio Module loaded successfully\n");
        
        return SWITCH_STATUS_SUCCESS;
    }

    SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_ws_audio_shutdown) {
        auto* module = WebSocketAudioModule::instance();

        if (module) {
            module->shutdown();
        }
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                        "WebSocket Audio Module unloaded\n");
        
        return SWITCH_STATUS_SUCCESS;
    }

}