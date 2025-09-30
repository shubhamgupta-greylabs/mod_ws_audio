#ifndef AUDIO_SESSION_HANDLER_H
#define AUDIO_SESSION_HANDLER_H

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <queue>
#include <switch.h>

class AudioSession {
private:
    std::string call_uuid_;
    switch_core_session_t* session_;
    switch_channel_t* channel_;
    switch_media_bug_t* read_bug_;
    switch_media_bug_t* write_bug_;
    struct lws* websocket_;
    
    // Audio playback
    std::atomic<bool> audio_playing_;
    std::vector<uint8_t> audio_buffer_;
    size_t audio_buffer_pos_;
    std::mutex audio_mutex_;

    // Audio queue for incoming audio data
    std::queue<std::vector<uint8_t>> audio_queue;
    std::mutex queue_mutex;
    
    // Media bug callbacks
    static switch_bool_t read_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type);
    static switch_bool_t write_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type);
    
public:
    AudioSession(const std::string& uuid, switch_core_session_t* session, struct lws* ws);
    ~AudioSession();
    
    // Core functionality
    bool start_streaming();
    bool stop_streaming();
    bool play_audio(const std::vector<uint8_t>& audio_data, switch_size_t len);
    bool stop_audio();
    
    // Getters
    const std::string& get_uuid() const { return call_uuid_; }
    struct lws* get_websocket() const { return websocket_; }
    bool is_playing() const { return audio_playing_.load(); }
    
    // WebSocket communication
    bool send_json_message(const std::string& message);
    bool send_audio_data(const void* data, size_t len);
    void queue_audio(const uint8_t* data, size_t len);
    bool pop_audio_chunk(std::vector<uint8_t>& chunk);

private:
    void cleanup_media_bugs();
    void cleanup_audio_buffer();
    void notify_audio_finished(bool interrupted = false);
};

#endif // AUDIO_SESSION_HANDLER_H