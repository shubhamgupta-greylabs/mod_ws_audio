#ifndef WEBSOCKET_HANDLER_H
#define WEBSOCKET_HANDLER_H

#include <string>
#include <unordered_map>
#include <atomic>
#include <memory>
#include <libwebsockets.h>
#include "audio_session_handler.h"

/**
 * WebSocket Audio Module - main module class
 */
class WebSocketAudioModule {
private:

    // Session management
    std::unordered_map<std::string, std::shared_ptr<AudioSession>> call_sessions;
    std::mutex call_sessions_mutex_;

    // Memory management
    switch_memory_pool_t* memory_pool_;
    switch_mutex_t* module_mutex_;
    
    // WebSocket callbacks
    static int websocket_callback(struct lws* wsi, enum lws_callback_reasons reason,
                                void* user, void* in, size_t len);
    
public:
    WebSocketAudioModule();
    ~WebSocketAudioModule();
    
    // Module lifecycle
    bool initialize(switch_loadable_module_interface_t** module_interface, switch_memory_pool_t* pool);
    void shutdown();
    
    // WebSocket server control
    bool connect_to_websocket_server(std::string host, int port, std::string call_uuid);
    
    // Session management
    std::shared_ptr<AudioSession> get_audio_session(const std::string& uuid);
    void remove_session_by_uuid(std::string call_uuid);
    
    // WebSocket event handling
    bool disconnect_websocket_client(std::string call_uuid);

    static WebSocketAudioModule* instance() { 
        static std::unique_ptr<WebSocketAudioModule> g_module;
        if (!g_module) {
            g_module = std::unique_ptr<WebSocketAudioModule>(new WebSocketAudioModule());
        }

        return g_module.get(); 
    }
};

#endif