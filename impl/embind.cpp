#include <emscripten/bind.h>
#include "smcrypto.h"

EMSCRIPTEN_BINDINGS(smsigner)
{
    emscripten::function("sign", &pl::sign);
    emscripten::function("verify", &pl::verify);
    emscripten::register_vector<uint8_t>("vector<byte>");
    emscripten::constant("RSA", pl::RSA);
    emscripten::constant("EC", pl::EC);
    emscripten::constant("SM", pl::SM);
}
