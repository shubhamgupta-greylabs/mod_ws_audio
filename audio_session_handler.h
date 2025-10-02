#ifndef AUDIO_SESSION_HANDLER_H
#define AUDIO_SESSION_HANDLER_H

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <queue>
#include <thread>
#include <switch.h>
#include <libwebsockets.h>

class AudioSession {
private:
    std::string call_uuid_;
    switch_core_session_t* session_;
    switch_channel_t* channel_;
    switch_media_bug_t* read_bug_;
    switch_media_bug_t* write_bug_;
    struct lws* websocket_;
    std::atomic<bool> running;
    std::thread ws_thread_;
    struct lws_context* ws_context_;

    // Host Info
    std::string ws_host_;
    int ws_port_;
    
    // Audio playback
    std::atomic<bool> audio_playing_;
    std::vector<int16_t> audio_buffer_;
    size_t audio_buffer_pos_;
    std::mutex audio_mutex_;

    // Audio queue for incoming audio data
    std::queue<std::vector<int16_t>> audio_queue;
    std::mutex queue_mutex;
    
    // Media bug callbacks
    static switch_bool_t read_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type);
    static switch_bool_t write_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type);
    
        // WebSocket callbacks
    static int websocket_callback(struct lws* wsi, enum lws_callback_reasons reason,
                                void* user, void* in, size_t len);

    static std::vector<int16_t> resample_16k_to_8k(const std::vector<int16_t>& input, size_t inputSamples);
public:
    AudioSession(const std::string& uuid, switch_core_session_t* session, std::string host, int port);
    ~AudioSession();
    
    // Core functionality
    bool start_streaming();
    bool stop_streaming();
    bool play_audio(const std::vector<int16_t>& audio_data, switch_size_t len);
    bool stop_audio();

    std::string ws_msg_buffer; //TODO: Create getter/setter and make the variable private
    
    // Getters
    bool is_playing() const { return audio_playing_.load(); }
    std::string get_uuid() { return call_uuid_; }
    
    // WebSocket communication
    bool send_json_message(const std::string& message);
    bool send_audio_data(const void* data, size_t len);
    bool pop_audio_chunk(std::vector<int16_t>& chunk);

    // Websocket event handling
    void connect(std::string host, int port);
    void handle_websocket_message(struct lws* wsi, const std::string& message);
    void handle_websocket_connection();
    void handle_websocket_disconnection();
    bool disconnect_websocket_client();

    //Websocket thread
    void websocket_client_thread();

    static std::string strip_ws_scheme(const std::string& url) {
        if (url.rfind("ws://", 0) == 0) {       
            return url.substr(5);               
        } else if (url.rfind("wss://", 0) == 0) { 
            return url.substr(6);               
        }
        return url; 
    }

        // Custom logging function
    static void lws_logger(int level, const char *line) {
        if (level & LLL_ERR) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "LWS: %s", line);
        }
    }
private:
    void cleanup_media_bugs();
    void cleanup_audio_buffer();
    void notify_audio_finished(bool interrupted = false);
};

#endif // AUDIO_SESSION_HANDLER_H