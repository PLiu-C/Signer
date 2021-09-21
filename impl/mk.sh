# g++ -static -std=c++17 -O3 -I/usr/local/include/botan-3 -o sign signer-test.cpp signer-botan.cpp /usr/local/lib/libbotan-3.a -lpthread
# g++ -static -std=c++17 -g -I/usr/local/include/botan-3 -o encdec signer-botan.cpp /home/pliu/crypto-libs/botan/libbotan-3.a -lpthread
g++  -fstack-protector -D_REENTRANT -m64 -std=c++11 -stdlib=libc++ -pthread -g -I/usr/local/include/botan-2 -o test sign_verify_embind.cpp /Users/pliu/botan/libbotan-2.a -ldl
