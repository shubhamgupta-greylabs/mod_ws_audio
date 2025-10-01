#include <mutex>
#include <vector>
#include <string>
#include <thread>
#include <libwebsockets.h>
#include <switch.h>
#include "audio_session_handler.h"
#include "websocket_handler.h"

/**
 * WebSocketAudioModule Implementation
 */
WebSocketAudioModule::WebSocketAudioModule() 
    : ws_context_(nullptr), ws_running_(false), ws_port_(0),
      memory_pool_(nullptr), module_mutex_(nullptr) {
}

WebSocketAudioModule::~WebSocketAudioModule() {
    shutdown();
}

bool WebSocketAudioModule::initialize(switch_loadable_module_interface_t** module_interface, switch_memory_pool_t* pool) {
    // Create memory pool and mutex
    switch_core_new_memory_pool(&memory_pool_);
    switch_mutex_init(&module_mutex_, SWITCH_MUTEX_NESTED, memory_pool_);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocketAudioModule initialized\n");
    return true;
}

void WebSocketAudioModule::shutdown() {
    for (auto& pair : call_sessions) {
        pair.second->disconnect_websocket_client();
    }
    
    // Clear all sessions
    {
        std::lock_guard<std::mutex> lock(call_sessions_mutex_);
        call_sessions.clear();
    }
    
    if (module_mutex_) {
        switch_mutex_destroy(module_mutex_);
        module_mutex_ = nullptr;
    }
    
    if (memory_pool_) {
        switch_core_destroy_memory_pool(&memory_pool_);
        memory_pool_ = nullptr;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocketAudioModule shutdown complete\n");
}

bool WebSocketAudioModule::disconnect_websocket_client(std::string call_uuid) {
    auto audio_session = get_audio_session(call_uuid);

    if (audio_session) {
        audio_session->disconnect_websocket_client();
    }

    return true;
}

bool WebSocketAudioModule::connect_to_websocket_server(
    std::string host, int port, std::string call_uuid) {

    switch_core_session_t* session = switch_core_session_locate(call_uuid.c_str());
    auto audio_session = std::make_shared<AudioSession>(call_uuid, session, host, port);

    {
        std::lock_guard<std::mutex> lock(call_sessions_mutex_);
        call_sessions[call_uuid] = audio_session;
    }
    
    audio_session->connect(host, port);

    return true;
}

std::shared_ptr<AudioSession> WebSocketAudioModule::get_audio_session(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(call_sessions_mutex_);
    auto it = call_sessions.find(uuid);
    return (it != call_sessions.end()) ? it->second : nullptr;
}

void WebSocketAudioModule::remove_session_by_uuid(std::string call_uuid) {
    std::lock_guard<std::mutex> lock(call_sessions_mutex_);
    
    auto it = call_sessions.find(call_uuid);
    if (it != call_sessions.end()) {
        call_sessions.erase(call_uuid);
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                         "Removed session by websocket for UUID: %s\n", call_uuid.c_str());
    }
}