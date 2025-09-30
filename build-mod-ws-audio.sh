#!/bin/bash
### Initial one liner:
# sudo apt-get -y install git \
#    && cd /usr/src/ \
#    && git clone https://github.com/shubhamgupta-greylabs/mod_ws_audio.git \
#    && cd mod_audio_stream \
#    && sudo bash ./build-mod-audio-stream.sh

apt-get -y install libssl-dev zlib1g-dev

git submodule init
git submodule update

FS_PKGCONFIG=/usr/local/freeswitch/lib/pkgconfig
if [ -d "$FS_PKGCONFIG" ]; then
    export PKG_CONFIG_PATH=$FS_PKGCONFIG
fi

# Delete existing build directory if it exists
if [ -d "build" ]; then
    echo "Removing existing build directory..."
    rm -rf build
fi

mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
make install