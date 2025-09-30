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
    disconnect_websocket_client();
    
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

bool WebSocketAudioModule::connect_to_websocket_server(std::string host, int port) {
    if (ws_running_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, 
                         "WebSocket client already running on host:port %s:%d\n", ws_host_.c_str(), ws_port_);
        return false;
    }
    
    ws_host_ = host;
    ws_port_ = port;
    ws_running_ = true;
    
    // Start server thread
    ws_thread_ = std::thread(&WebSocketAudioModule::websocket_client_thread, this);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server starting on host:port %s:%d\n", host.c_str(), port);
    return true;
}

bool WebSocketAudioModule::disconnect_websocket_client() {
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
                     "WebSocket client disconnected\n");
    return true;
}

void WebSocketAudioModule::websocket_client_thread() {
    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO, lws_logger);

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
    info.port = CONTEXT_PORT_NO_LISTEN;
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

    std::string hostName = strip_ws_scheme(ws_host_);
    
    struct lws_client_connect_info ccinfo = {};
    ccinfo.context = ws_context_;
    ccinfo.address = hostName.c_str();
    ccinfo.port = ws_port_;
    ccinfo.path = "/";
    ccinfo.host = hostName.c_str();
    ccinfo.origin = "freeswitch";
    ccinfo.protocol = "ws-audio-protocol";

    struct lws* wsi = lws_client_connect_via_info(&ccinfo);
    if (!wsi) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                         "Failed to initiate WebSocket client connection\n");
        ws_running_ = false;
        return;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                     "WebSocket client thread started, connecting to %s:%d\n",
                     ws_host_.c_str(), ws_port_);

    while (ws_running_) {
        lws_service(ws_context_, 20);
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
                "{\"status\":\"ok\",\"message\":\"Audio streaming started\",\"uuid\":\"" + uuid + "\"}":
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
                switch_size_t approx_decoded_len =  strlen(audio_data->valuestring) / 4 * 3;

                char* decoded_audio = (char*)malloc(approx_decoded_len); 

                switch_size_t decoded_len = switch_b64_decode(audio_data->valuestring, decoded_audio, approx_decoded_len);
                
                if (decoded_audio && decoded_len > 0) {
                    std::vector<uint8_t> audio_vec(decoded_audio, decoded_audio + decoded_len);
                    bool success = session->play_audio(audio_vec, decoded_len);
                    
                    std::string response = success ?
                        "{\"status\":\"ok\",\"message\":\"Audio playback started\",\"uuid\":\"" + uuid + "\"}":
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
    auto* session = module->get_session_by_websocket(wsi).get();

    if (!module) return -1;
    
    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        module->handle_websocket_connection(wsi);
        break;
        
    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (in && len > 0) {
            std::string message(static_cast<char*>(in), len);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                             "Received WebSocket message: %s\n", message.c_str());
            module->handle_websocket_message(wsi, message);
        }
        break;
        
    case LWS_CALLBACK_CLOSED:
        module->handle_websocket_disconnection(wsi);
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        if (session) {
            std::vector<uint8_t> audio_chunk;
            if (session->pop_audio_chunk(audio_chunk)) {
                std::vector<unsigned char> buf(LWS_PRE + audio_chunk.size());
                memcpy(buf.data() + LWS_PRE, audio_chunk.data(), audio_chunk.size());

                int n = lws_write(wsi, buf.data() + LWS_PRE, audio_chunk.size(), LWS_WRITE_BINARY);
                if (n < (int)audio_chunk.size()) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                    "Failed to send full audio chunk: %d/%zu\n", n, audio_chunk.size());
                }
            }
        }
        
    default:
        break;
    }
    
    return 0;
}
