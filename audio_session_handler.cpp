/**
 * Audio Session - handles individual call audio streaming
 */
#include <string>
#include <vector>
#include <thread>
#include <libwebsockets.h>
#include <switch.h>
#include "audio_session_handler.h"
#include <libwebsockets.h>
#include <samplerate.h>
#include <speex/speex_resampler.h>
#include <stdexcept>

/**
 * AudioSession Implementation
 */
AudioSession::AudioSession(const std::string& uuid, switch_core_session_t* session, std::string host, int port)
    : call_uuid_(uuid), session_(session), websocket_(nullptr), 
      read_bug_(nullptr), write_bug_(nullptr),
      audio_playing_(false), audio_buffer_pos_(0), ws_host_(host), ws_port_(port), running(false) {
    
    channel_ = switch_core_session_get_channel(session_);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Created AudioSession for UUID: %s\n", uuid.c_str());
    
    int channels = 1;
    spx_uint32_t in_rate = 16000, out_rate = 8000;
    int quality = 10;
    int err;
    resampler = speex_resampler_init(channels, in_rate, out_rate, quality, &err);
    if (!resampler || err != RESAMPLER_ERR_SUCCESS) {
        throw std::runtime_error("Failed to initialize Speex resampler");
    }
}

AudioSession::~AudioSession() {
    cleanup_media_bugs();
    cleanup_audio_buffer();
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "Destroyed AudioSession for UUID: %s\n", call_uuid_.c_str());
}

void AudioSession::connect(std::string host, int port) {

    running = true;
    ws_host_ = host;
    ws_port_ = port;

    ws_thread_ = std::thread(&AudioSession::websocket_client_thread, this);
}

void AudioSession::websocket_client_thread() {
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
        running = false;
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

    websocket_ = lws_client_connect_via_info(&ccinfo);
    if (!websocket_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                         "Failed to initiate WebSocket client connection\n");
        running = false;
        return;
    }

    lws_set_wsi_user(websocket_, this);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                     "WebSocket client thread started, connecting to %s:%d\n",
                     ws_host_.c_str(), ws_port_);

    while (running) {
        lws_service(ws_context_, 20);
    }
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket server thread exiting\n");
}

bool AudioSession::disconnect_websocket_client() {
    if (!running) {
        return true;
    }
    
    running = false;
    
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

// WebSocket callback function
int AudioSession::websocket_callback(struct lws* wsi, enum lws_callback_reasons reason,
                                            void* user, void* in, size_t len) {
                                                
    AudioSession* session = static_cast<AudioSession*>(lws_wsi_user(wsi));

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Session exists %s\n", session ? "true": "false");
                        
    if (!session) return 0;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Callback reason %d, %d\n", reason, LWS_CALLBACK_CLIENT_ESTABLISHED);

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
                              "WebSocket connected for call %s\n", session->call_uuid_.c_str());

            // Prepare verification JSON
            std::string init_msg = "{\"status\":\"ok\",\"message\":\"connected\",\"uuid\":\"" + session->call_uuid_ + "\"}";

            session->send_json_message(init_msg);

            break;
        }
    case LWS_CALLBACK_ESTABLISHED:
        session->handle_websocket_connection();
        break;
        
    case LWS_CALLBACK_CLIENT_RECEIVE:
        try {
            if (in && len > 0) {
                session->ws_msg_buffer.append((const char*)in, len);

                if (lws_is_final_fragment(wsi) && lws_remaining_packet_payload(wsi) == 0) {
                    std::string message = session->ws_msg_buffer;

                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                    "Received WebSocket message: %s\n", message.c_str());
                    session->handle_websocket_message(wsi, message);

                    session->ws_msg_buffer.clear();
                }
            }
        } catch(const std::exception& e) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                             "Exception in WebSocket receive handling: %s\n", e.what());
        }
        break;
        
    case LWS_CALLBACK_CLOSED:
        session->handle_websocket_disconnection();
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE: {
        std::vector<int16_t> audio_chunk;
        if (session->pop_audio_chunk(audio_chunk)) {
            std::vector<unsigned char> buf(LWS_PRE + audio_chunk.size());
            memcpy(buf.data() + LWS_PRE, audio_chunk.data(), audio_chunk.size());

            int n = lws_write(wsi, buf.data() + LWS_PRE, audio_chunk.size(), LWS_WRITE_BINARY);
            if (n < (int)audio_chunk.size()) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                                "Failed to send full audio chunk: %d/%zu\n", n, audio_chunk.size());
            }
        }
        break;
    }
        
    default:
        break;
    }
    
    return 0;
}

void AudioSession::handle_websocket_message(struct lws* wsi, const std::string& message) {

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

    switch_core_session_t* session = switch_core_session_locate(uuid.c_str());

    // Handle different commands
    if (cmd == "start_audio") {   
        // Get FreeSWITCH session        
        if (session) {
            bool success = start_streaming();
        
            std::string response = success ? 
                "{\"status\":\"ok\",\"message\":\"Audio streaming started\",\"uuid\":\"" + uuid + "\"}":
                R"({"status":"error","message":"Failed to start streaming"})";
        
            send_json_message(response);
        
            switch_core_session_rwunlock(session);
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                             "Session not found: %s\n", uuid.c_str());
        }
    }
    else if (cmd == "play_audio") {
        cJSON* audio_data = cJSON_GetObjectItem(json, "audio_data");
        if (audio_data && audio_data->valuestring) {

            if (session) {
                switch_size_t approx_decoded_len =  strlen(audio_data->valuestring) / 4 * 3;

                char* decoded_audio = (char*)malloc(approx_decoded_len); 

                switch_size_t decoded_len = switch_b64_decode(audio_data->valuestring, decoded_audio, approx_decoded_len);
                
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                 "Decoded audio data is %s bytes having len %zu\n", decoded_audio, decoded_len);

                if (decoded_audio && decoded_len > 0) {
                    std::vector<int16_t> audio_vec(decoded_audio, decoded_audio + decoded_len);
                    bool success = play_audio(audio_vec, decoded_len);
                    
                    switch_safe_free(decoded_audio);
                }
            }
        }
    }
    else if (cmd == "stop_audio") {
        if (session) {
            stop_audio();
        }
    }
    else if (cmd == "stop_streaming") {
        if (session) {
            stop_streaming();
            // TODO: Might need to remove the websocket connection too

            std::string response = R"({"status":"ok","message":"Audio streaming stopped"})";
            send_json_message(response);
        }
    }
    
    cJSON_Delete(json);
}

void AudioSession::handle_websocket_connection() {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket connection established\n");
}

void AudioSession::handle_websocket_disconnection() {

    stop_streaming();

    /**
     *  TODO: Need to remove session from WebSocketAudioModule without
     *  creating circular dependency
     * */ 
    // auto* module = WebSocketAudioModule::instance();

    // module->remove_session_by_uuid(call_uuid_);
    
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                     "WebSocket connection closed\n");
}

bool AudioSession::start_streaming() {
    if (!session_ || !channel_) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                         "Invalid session or channel for UUID: %s\n", call_uuid_.c_str());
        return false;
    }

    switch_media_bug_flag_t flags = 
        SMBF_WRITE_REPLACE | 
        SMBF_READ_REPLACE | 
        SMBF_WRITE_STREAM |    // ← This is the key
        SMBF_READ_STREAM |     // ← For reading raw audio too
        SMBF_ANSWER_REQ | 
        SMBF_NO_PAUSE;
    
    // Add media bug for reading audio from call
    switch_status_t status = switch_core_media_bug_add(
        session_, "ws_audio_read", nullptr,
        read_audio_callback, this, 0,
        flags, &read_bug_
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
        flags, &write_bug_
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

std::vector<int16_t> AudioSession::resample_16k_to_8k(const std::vector<int16_t>& in) {
    
    spx_uint32_t in_rate = 16000, out_rate = 8000;
    std::vector<int16_t> out;

    spx_uint32_t in_len = in.size();
    spx_uint32_t out_len = in.size() * out_rate / in_rate + 16;
    out.resize(out_len);

    speex_resampler_process_int(resampler, 0, in.data(), &in_len, out.data(), &out_len);
    out.resize(out_len);

    return out;
}


bool AudioSession::play_audio(const std::vector<int16_t>& audio_data, size_t len) {    
    std::vector<int16_t> audio_samples_8k = resample_16k_to_8k(audio_data);

    size_t frame_len = 320, offset = 0;

    audio_buffer_.insert(audio_buffer_.end(), audio_samples_8k.begin(), audio_samples_8k.end());

    if (audio_buffer_.size() >= frame_len) {
        std::lock_guard<std::mutex> lock(queue_mutex);

        while (offset < audio_buffer_.size()) {
            size_t remaining = audio_buffer_.size() - offset;
            size_t slice_len = std::min(frame_len, remaining);

            audio_queue.emplace(audio_buffer_.begin(), audio_buffer_.begin() + offset + slice_len);
            offset += slice_len;
        }

        audio_playing_ = true;
    
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                     "Started audio playback for UUID: %s, size: %zu bytes\n", 
                     call_uuid_.c_str(), audio_buffer_.size());
        
        audio_buffer_.clear();
    }

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

bool AudioSession::pop_audio_chunk(std::vector<int16_t>& chunk) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                     "Popping audio chunk for UUID: %s, queue size: %zu\n", call_uuid_.c_str(), audio_queue.size());

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
                if (frame.data && frame.datalen > 0) {
                    // Send audio data to WebSocket client
                    session->send_audio_data(static_cast<const uint8_t*>(frame.data), frame.datalen);
                }
            }
        }
        break;
    default:
        break;
    }
    
    return SWITCH_TRUE;
}

uint8_t AudioSession::linear_to_ulaw(int16_t sample) {
    const int cBias = 0x84;
    const int cClip = 32635;

    int sign = (sample >> 8) & 0x80;
    if (sign) sample = -sample;
    if (sample > cClip) sample = cClip;
    sample += cBias;

    int exponent = 7;
    for (int expMask = 0x4000; (sample & expMask) == 0 && exponent > 0; expMask >>= 1) {
        exponent--;
    }

    int mantissa = (sample >> ((exponent == 0) ? 4 : (exponent + 3))) & 0x0F;
    uint8_t ulawByte = ~(sign | (exponent << 4) | mantissa);

    return ulawByte;
}

void AudioSession::log_frame_bytes(switch_frame_t* frame, size_t max_bytes = 32) {
    uint8_t* data = (uint8_t*)frame->data;
    size_t n = frame->datalen < max_bytes ? frame->datalen : max_bytes;

    char hexbuf[4];
    std::string hexstr;
    for (size_t i = 0; i < n; ++i) {
        snprintf(hexbuf, sizeof(hexbuf), "%02x ", data[i]);
        hexstr += hexbuf;
    }
    if (frame->datalen > max_bytes) hexstr += "...";

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
                      "Frame bytes (%zu bytes): %s\n", frame->datalen, hexstr.c_str());
}

// Media bug callback for writing audio
switch_bool_t AudioSession::write_audio_callback(switch_media_bug_t* bug, void* user_data, switch_abc_type_t type) {
    auto* session = static_cast<AudioSession*>(user_data);

    switch (type) {
        case SWITCH_ABC_TYPE_WRITE_REPLACE: {
                if (session->is_playing()) {
                    switch_frame_t* frame = switch_core_media_bug_get_write_replace_frame(bug);
                    if (frame && frame->data) {
                        std::lock_guard<std::mutex> lock(session->queue_mutex);

                        std::vector<int16_t> audio_chunk;
                        if (session->pop_audio_chunk(audio_chunk)) {
                            std::vector<uint8_t> converted_chunk(audio_chunk.size());
                            for (int i=0; i<audio_chunk.size(); ++i) {
                                converted_chunk[i] = linear_to_ulaw(audio_chunk[i]);
                            }
                            size_t to_copy = std::min(converted_chunk.size(), (size_t)frame->datalen);
                            memcpy(frame->data, converted_chunk.data(), to_copy);
                            frame->datalen = to_copy;
                            log_frame_bytes(frame);

                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                             "Wrote %zu bytes of audio data for UUID: %s\n", to_copy, session->call_uuid_.c_str());

                            // Check if finished playing
                            if (session->audio_queue.empty()) {
                                session->audio_playing_ = false;
                                session->notify_audio_finished(false);
                                // session->cleanup_audio_buffer();
                            }
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
