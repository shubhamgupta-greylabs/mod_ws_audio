#include <mutex>
#include <vector>
#include <string>
#include <thread>
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
    stop_websocket_server();
    
    // Clear all sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
        websocket_sessions_.clear();
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

bool WebSocketAudioModule::start_websocket_server(int port) {
    if (ws_running_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, 
                         "WebSocket server already running on port %d\n", ws_port_);
        return false;
    }
    
    ws_port_ = port;
    ws_running_ = true;
    
    // Start server thread
    ws_thread_ = std::thread(&WebSocketAudioModule::websocket_server_thread, this);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server starting on port %d\n", port);
    return true;
}

bool WebSocketAudioModule::stop_websocket_server() {
    if (!ws_running_) {
        return true;
    }
    
    ws_running_ = false;
    
    // Wait for thread to finish
    if (ws_thread_.joinable()) {
        ws_thread_.join();
    }
    
    if (ws_context_) {
        lws_context_destroy(ws_context_);
        ws_context_ = nullptr;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server stopped\n");
    return true;
}

void WebSocketAudioModule::websocket_server_thread() {
    struct lws_protocols protocols[] = {
        {
            "ws-audio-protocol",
            websocket_callback,
            0,
            4096,
        },
        { nullptr, nullptr, 0, 0 } // terminator
    };
    
    struct lws_context_creation_info info = {};
    info.port = ws_port_;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    
    ws_context_ = lws_create_context(&info);
    if (!ws_context_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to create WebSocket context\n");
        ws_running_ = false;
        return;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server started on port %d\n", ws_port_);
    
    while (ws_running_) {
        lws_service(ws_context_, 50);
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server thread exiting\n");
}

std::shared_ptr<AudioSession> WebSocketAudioModule::create_session(const std::string& uuid, 
                                                                  switch_core_session_t* session, 
                                                                  struct lws* ws) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto audio_session = std::make_shared<AudioSession>(uuid, session, ws);
    sessions_[uuid] = audio_session;
    websocket_sessions_[ws] = audio_session;
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Created session for UUID: %s\n", uuid.c_str());
    return audio_session;
}

std::shared_ptr<AudioSession> WebSocketAudioModule::get_session(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(uuid);
    return (it != sessions_.end()) ? it->second : nullptr;
}

std::shared_ptr<AudioSession> WebSocketAudioModule::get_session_by_websocket(struct lws* ws) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = websocket_sessions_.find(ws);
    return (it != websocket_sessions_.end()) ? it->second : nullptr;
}

void WebSocketAudioModule::remove_session(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(uuid);
    if (it != sessions_.end()) {
        // Remove from websocket map too
        for (auto ws_it = websocket_sessions_.begin(); ws_it != websocket_sessions_.end(); ++ws_it) {
            if (ws_it->second == it->second) {
                websocket_sessions_.erase(ws_it);
                break;
            }
        }
        sessions_.erase(it);
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                         "Removed session for UUID: %s\n", uuid.c_str());
    }
}

void WebSocketAudioModule::remove_session_by_websocket(struct lws* ws) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = websocket_sessions_.find(ws);
    if (it != websocket_sessions_.end()) {
        std::string uuid = it->second->get_uuid();
        websocket_sessions_.erase(it);
        sessions_.erase(uuid);
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                         "Removed session by websocket for UUID: %s\n", uuid.c_str());
    }
}

void WebSocketAudioModule::handle_websocket_connection(struct lws* wsi) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket connection established\n");
}

void WebSocketAudioModule::handle_websocket_message(struct lws* wsi, const std::string& message) {
    // Parse JSON command
    cJSON* json = cJSON_Parse(message.c_str());
    if (!json) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to parse JSON: %s\n", message.c_str());
        return;
    }
    
    cJSON* command = cJSON_GetObjectItem(json, "command");
    cJSON* uuid_item = cJSON_GetObjectItem(json, "uuid");
    
    if (!command || !uuid_item) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Missing command or uuid in JSON\n");
        cJSON_Delete(json);
        return;
    }
    
    std::string cmd = command->valuestring;
    std::string uuid = uuid_item->valuestring;
    
    // Handle different commands
    if (cmd == "start_audio") {
        // Get FreeSWITCH session
        switch_core_session_t* session = switch_core_session_locate(uuid.c_str());
        if (session) {
            auto audio_session = create_session(uuid, session, wsi);
            bool success = audio_session->start_streaming();
            
            std::string response = success ? 
                R"({"status":"ok","message":"Audio streaming started"})" :
                R"({"status":"error","message":"Failed to start streaming"})";
            audio_session->send_json_message(response);
            
            switch_core_session_rwunlock(session);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                             "Session not found: %s\n", uuid.c_str());
        }
    }
    else if (cmd == "play_audio") {
        cJSON* audio_data = cJSON_GetObjectItem(json, "audio_data");
        if (audio_data && audio_data->valuestring) {
            auto session = get_session(uuid);
            if (session) {
                // Decode base64 audio data
                size_t decoded_len = 0;
                char* decoded_audio = switch_b64_decode(audio_data->valuestring, &decoded_len);
                
                if (decoded_audio && decoded_len > 0) {
                    std::vector<uint8_t> audio_vec(decoded_audio, decoded_audio + decoded_len);
                    bool success = session->play_audio(audio_vec);
                    
                    std::string response = success ?
                        R"({"status":"ok","message":"Audio playback started"})" :
                        R"({"status":"error","message":"Failed to start playback"})";
                    session->send_json_message(response);
                    
                    switch_safe_free(decoded_audio);
                }
            }
        }
    }
    else if (cmd == "stop_audio") {
        auto session = get_session(uuid);
        if (session) {
            session->stop_audio();
        }
    }
    else if (cmd == "stop_streaming") {
        auto session = get_session(uuid);
        if (session) {
            session->stop_streaming();
            remove_session(uuid);
            
            std::string response = R"({"status":"ok","message":"Audio streaming stopped"})";
            session->send_json_message(response);
        }
    }
    
    cJSON_Delete(json);
}

void WebSocketAudioModule::handle_websocket_disconnection(struct lws* wsi) {
    auto session = get_session_by_websocket(wsi);
    if (session) {
        session->stop_streaming();
        remove_session_by_websocket(wsi);
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket connection closed\n");
}

// WebSocket callback function
int WebSocketAudioModule::websocket_callback(struct lws* wsi, enum lws_callback_reasons reason,
                                            void* user, void* in, size_t len) {
    
    auto* module = WebSocketAudioModule::instance();
    if (!module) return -1;
    
    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        module->handle_websocket_connection(wsi);
        break;
        
    case LWS_CALLBACK_RECEIVE:
        if (in && len > 0) {
            std::string message(static_cast<char*>(in), len);
            module->handle_websocket_message(wsi, message);
        }
        break;
        
    case LWS_CALLBACK_CLOSED:
        module->handle_websocket_disconnection(wsi);
        break;
        
    default:
        break;
    }
    
    return 0;
}
