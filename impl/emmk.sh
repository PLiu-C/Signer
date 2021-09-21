BOTAN_INC_PATH=/Users/pliu/neo/github/botan/include/botan-2
BOTAN_LIB_PATH=/Users/pliu/neo/github/botan/lib/wasm

FLAGS="-std=c++11 -O3 -fno-use-cxa-atexit -Wall -Wextra -Wpedantic -Wshadow -Wstrict-aliasing -Wstrict-overflow=5 -Wcast-align -Wmissing-declarations -Wpointer-arith -Wcast-qual"

em++ --bind -s FILESYSTEM=1 -s ALLOW_MEMORY_GROWTH=1 -s DISABLE_EXCEPTION_CATCHING=0 -s WASM=1 ${FLAGS} -I${BOTAN_INC_PATH} smcrypto.cpp embind.cpp ${BOTAN_LIB_PATH}/libbotan-2.a -o signer.html
