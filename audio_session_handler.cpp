/**
 * Audio Session - handles individual call audio streaming
 */
#include <string>
#include <vector>
#include <switch.h>
#include "audio_session_handler.h"
#include <libwebsockets.h>

/**
 * AudioSession Implementation
 */
AudioSession::AudioSession(const std::string& uuid, switch_core_session_t* session, struct lws* ws)
    : call_uuid_(uuid), session_(session), websocket_(ws), 
      read_bug_(nullptr), write_bug_(nullptr),
      audio_playing_(false), audio_buffer_pos_(0) {
    
    channel_ = switch_core_session_get_channel(session_);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Created AudioSession for UUID: %s\n", uuid.c_str());
}

AudioSession::~AudioSession() {
    cleanup_media_bugs();
    cleanup_audio_buffer();
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Destroyed AudioSession for UUID: %s\n", call_uuid_.c_str());
}

bool AudioSession::start_streaming() {
    if (!session_ || !channel_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Invalid session or channel for UUID: %s\n", call_uuid_.c_str());
        return false;
    }
    
    // Add media bug for reading audio from call
    switch_status_t status = switch_core_media_bug_add(
        session_, "ws_audio_read", nullptr,
        read_audio_callback, this, 0,
        SMBF_READ_REPLACE, &read_bug_
    );
    
    if (status != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to add read media bug for UUID: %s\n", call_uuid_.c_str());
        return false;
    }
    
    // Add media bug for writing audio to call
    status = switch_core_media_bug_add(
        session_, "ws_audio_write", nullptr,
        write_audio_callback, this, 0,
        SMBF_WRITE_REPLACE, &write_bug_
    );
    
    if (status != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Failed to add write media bug for UUID: %s\n", call_uuid_.c_str());
        cleanup_media_bugs();
        return false;
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Started audio streaming for UUID: %s\n", call_uuid_.c_str());
    return true;
}

bool AudioSession::stop_streaming() {
    cleanup_media_bugs();
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Stopped audio streaming for UUID: %s\n", call_uuid_.c_str());
    return true;
}

bool AudioSession::play_audio(const std::vector<uint8_t>& audio_data) {
    std::lock_guard<std::mutex> lock(audio_mutex_);
    
    // Stop current playback
    audio_playing_ = false;
    
    // Set new audio buffer
    audio_buffer_ = audio_data;
    audio_buffer_pos_ = 0;
    audio_playing_ = true;
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                     "Started audio playback for UUID: %s, size: %zu bytes\n", 
                     call_uuid_.c_str(), audio_data.size());
    return true;
}

bool AudioSession::stop_audio() {
    std::lock_guard<std::mutex> lock(audio_mutex_);
    
    if (audio_playing_) {
        audio_playing_ = false;
        cleanup_audio_buffer();
        notify_audio_finished(true); // interrupted
        
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                         "Stopped audio playback for UUID: %s\n", call_uuid_.c_str());
    }
    
    return true;
}

bool AudioSession::send_json_message(const std::string& message) {
    if (!websocket_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "WebSocket not connected for UUID: %s\n", call_uuid_.c_str());
        return false;
    }
    
    size_t msg_len = message.length();
    std::vector<unsigned char> buffer(LWS_SEND_BUFFER_PRE_PADDING + msg_len + LWS_SEND_BUFFER_POST_PADDING);
    unsigned char* payload = buffer.data() + LWS_SEND_BUFFER_PRE_PADDING;
    
    memcpy(payload, message.c_str(), msg_len);
    int result = lws_write(websocket_, payload, msg_len, LWS_WRITE_TEXT);
    
    return result >= 0;
}

bool AudioSession::send_audio_data(const void* data, size_t len) {
    if (!websocket_ || !data || len == 0) return false;
    
    std::vector<unsigned char> buffer(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING);
    unsigned char* payload = buffer.data() + LWS_SEND_BUFFER_PRE_PADDING;
    
    memcpy(payload, data, len);
    int result = lws_write(websocket_, payload, len, LWS_WRITE_BINARY);
    
    return result >= 0;
}

void AudioSession::cleanup_media_bugs() {
    if (read_bug_) {
        switch_core_media_bug_remove(session_, &read_bug_);
        read_bug_ = nullptr;
    }
    
    if (write_bug_) {
        switch_core_media_bug_remove(session_, &write_bug_);
        write_bug_ = nullptr;
    }
}

void AudioSession::cleanup_audio_buffer() {
    audio_buffer_.clear();
    audio_buffer_pos_ = 0;
}

void AudioSession::notify_audio_finished(bool interrupted) {
    std::string event_type = interrupted ? "interrupted" : "playback_complete";
    std::string json_msg = R"({"event":"audio_finished","type":")" + event_type + R"("})";
    
    if (interrupted) {
        json_msg = R"({"event":"audio_stopped","type":"interrupted"})";
    }
    
    send_json_message(json_msg);
}

void AudioSession::queue_audio(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    audio_queue.emplace(data, data + len);

    // Ask libwebsockets to call the writeable callback
    if (websocket_) {
        lws_callback_on_writable(websocket_);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                         "Queued audio data for UUID: %s, size: %zu bytes\n", call_uuid_.c_str(), len);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "WebSocket not connected for UUID: %s\n", call_uuid_.c_str());
    }
}

bool AudioSession::pop_audio_chunk(std::vector<uint8_t>& chunk) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    if (audio_queue.empty()) return false;
    chunk = std::move(audio_queue.front());
    audio_queue.pop();
    return true;
}

// Media bug callback for reading audio
switch_bool_t AudioSession::read_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type) {
    auto* session = static_cast<AudioSession*>(user_data);
    
    switch (type) {
    case SWITCH_ABC_TYPE_READ:
        {
            uint8_t data_buf[SWITCH_RECOMMENDED_BUFFER_SIZE];
            switch_frame_t frame = {0};
            frame.data = data_buf;
            frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;

            if (switch_core_media_bug_read(bug, &frame, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
                if (frame && frame->data && frame->datalen > 0) {
                    // Send audio data to WebSocket client
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                             "Read audio frame: datalen=%d\n", frame ? frame->datalen : -1);
                    session->send_audio_data(static_cast<const uint8_t*>(frame->data), frame->datalen);
                }
            }
        }
        break;
    default:
        break;
    }
    
    return SWITCH_TRUE;
}

// Media bug callback for writing audio
switch_bool_t AudioSession::write_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type) {
    auto* session = static_cast<AudioSession*>(user_data);
    
    switch (type) {
        case SWITCH_ABC_TYPE_WRITE: {
                if (session->is_playing()) {
                    switch_frame_t* frame = switch_core_media_bug_get_write_replace_frame(bug);
                    if (frame && frame->data) {
                        std::lock_guard<std::mutex> lock(session->audio_mutex_);
                        
                        uint32_t remaining = session->audio_buffer_.size() - session->audio_buffer_pos_;
                        uint32_t to_copy = std::min(remaining, frame->datalen);
                        
                        if (to_copy > 0) {
                            memcpy(frame->data, session->audio_buffer_.data() + session->audio_buffer_pos_, to_copy);
                            session->audio_buffer_pos_ += to_copy;
                            frame->datalen = to_copy;
                            
                            // Check if finished playing
                            if (session->audio_buffer_pos_ >= session->audio_buffer_.size()) {
                                session->audio_playing_ = false;
                                session->notify_audio_finished(false);
                                session->cleanup_audio_buffer();
                            }
                        } else {
                            // No more audio, send silence
                            memset(frame->data, 0, frame->datalen);
                        }
                    }
                }
            }
        break;
    default:
        break;
    }
    
    return SWITCH_TRUE;
}
