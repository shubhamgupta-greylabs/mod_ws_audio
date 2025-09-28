#ifndef WEBSOCKET_HANDLER_H
#define WEBSOCKET_HANDLER_H

#include <string>
#include <unordered_map>
#include <thread>
#include <atomic>
#include "audio_session_handler.h"

/**
 * WebSocket Audio Module - main module class
 */
class WebSocketAudioModule {
private:
    // WebSocket server
    struct lws_context* ws_context_;
    std::thread ws_thread_;
    std::atomic<bool> ws_running_;
    int ws_port_;
    
    // Session management
    std::unordered_map<std::string, std::shared_ptr<AudioSession>> sessions_;
    std::unordered_map<struct lws*, std::shared_ptr<AudioSession>> websocket_sessions_;
    std::mutex sessions_mutex_;
    
    // Memory management
    switch_memory_pool_t* memory_pool_;
    switch_mutex_t* module_mutex_;
    
    // WebSocket callbacks
    static int websocket_callback(struct lws* wsi, enum lws_callback_reasons reason,
                                void* user, void* in, size_t len);
    
    // Server thread
    void websocket_server_thread();
    
    // Websocket Instance
    static std::unique_ptr<WebSocketAudioModule> g_module;
    
public:
    WebSocketAudioModule();
    ~WebSocketAudioModule();
    
    // Module lifecycle
    bool initialize(switch_loadable_module_interface_t** module_interface, switch_memory_pool_t* pool);
    void shutdown();
    
    // WebSocket server control
    bool start_websocket_server(int port);
    bool stop_websocket_server();
    bool is_server_running() const { return ws_running_.load(); }
    int get_server_port() const { return ws_port_; }
    
    // Session management
    std::shared_ptr<AudioSession> create_session(const std::string& uuid, switch_core_session_t* session, struct lws* ws);
    std::shared_ptr<AudioSession> get_session(const std::string& uuid);
    std::shared_ptr<AudioSession> get_session_by_websocket(struct lws* ws);
    void remove_session(const std::string& uuid);
    void remove_session_by_websocket(struct lws* ws);
    
    // WebSocket event handling
    void handle_websocket_connection(struct lws* wsi);
    void handle_websocket_message(struct lws* wsi, const std::string& message);
    void handle_websocket_disconnection(struct lws* wsi);
    
    // Static access for C callbacks
    static WebSocketAudioModule* instance() { 
        if (!g_module) {
            g_module = std::unique_ptr<WebSocketAudioModule>(new WebSocketAudioModule());
        }

        return g_module.get(); 
    }
};

#endif // WEBSOCKET_HANDLER_H