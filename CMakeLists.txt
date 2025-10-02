cmake_minimum_required(VERSION 3.18)
project(mod_ws_audio
        VERSION 1.0.0
        DESCRIPTION "Audio streaming module for FreeSWITCH.")

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")

option(ENABLE_LOCAL "Enable local compile/debug specific" OFF)
if(ENABLE_LOCAL)
    set(ENV{PKG_CONFIG_PATH} "/usr/local/freeswitch/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(PkgConfig REQUIRED)

# find libwebsockets
pkg_check_modules(LIBWEBSOCKETS REQUIRED libwebsockets)
# find libsamplerate
pkg_check_modules(SAMPLERATE REQUIRED samplerate)

find_path(SPEEXDSP_INCLUDE_DIR NAMES speex/speex_resampler.h)
find_library(SPEEXDSP_LIBRARY NAMES speexdsp)

if(NOT SPEEXDSP_INCLUDE_DIR OR NOT SPEEXDSP_LIBRARY)
    message(FATAL_ERROR "SpeexDSP not found. Install libspeexdsp-dev")
endif()

include_directories(${SAMPLERATE_INCLUDE_DIRS})

pkg_check_modules(FreeSWITCH REQUIRED IMPORTED_TARGET freeswitch)
pkg_get_variable(FS_MOD_DIR freeswitch modulesdir)
message(STATUS "FreeSWITCH modules dir: ${FS_MOD_DIR}")

add_library(mod_ws_audio SHARED 
    mod_ws_audio.cpp
    websocket_handler.cpp
    audio_session_handler.cpp
)

set_property(TARGET mod_ws_audio PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(mod_ws_audio PRIVATE 
    PkgConfig::FreeSWITCH 
    pthread
)

include_directories(${SPEEXDSP_INCLUDE_DIR})

target_link_libraries(mod_ws_audio PRIVATE ${SPEEXDSP_LIBRARY})

target_include_directories(mod_ws_audio PRIVATE ${SAMPLERATE_INCLUDE_DIRS})
target_link_libraries(mod_ws_audio PRIVATE ${SAMPLERATE_LIBRARIES})

target_link_libraries(mod_ws_audio PRIVATE 
    PkgConfig::FreeSWITCH 
    pthread
    ${LIBWEBSOCKETS_LIBRARIES}
)
target_include_directories(mod_ws_audio PRIVATE
    ${LIBWEBSOCKETS_INCLUDE_DIRS}
)

if(CMAKE_BUILD_TYPE MATCHES "Release")
    set_target_properties(${PROJECT_NAME} 
        PROPERTIES 
        LINK_FLAGS_RELEASE "-s")
endif()


install(TARGETS ${PROJECT_NAME}
        COMPONENT ${PROJECT_NAME}
        DESTINATION ${FS_MOD_DIR})

        
message(STATUS "Components to pack: ${CPACK_COMPONENTS_ALL}")