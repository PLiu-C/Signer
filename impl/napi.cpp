#include <napi.h>
#include <cassert>
#include "smcrypto.h"


typedef Napi::Buffer<uint8_t> Buffer;

/* Wrapper for smencrypt / smedecrypt
Napi::Value smencrypt(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    try {
        auto msg = info[0].As<Buffer>();   // plaintext to be encrypted
        auto pubkey = info[1].As<Napi::String>();  // pubkey in pem base64 format
        auto ct = pl::smencrypt(static_cast<std::string>(pubkey).c_str(), msg.Data(), msg.Length());
        return Napi::String::New(env, ct);
    } catch (const std::exception& e) {
        throw Napi::Error::New(env, e.what());
    }
}

Napi::Value smdecrypt(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    try {
        auto ct0 = info[0].As<Napi::String>();     // ciphertext base64 encoded
        auto prikey = info[1].As<Napi::String>(); // private key in pkcs8 bas64 format
        auto ct = static_cast<std::string>(ct0);
        auto pt = pl::smdecrypt(static_cast<std::string>(prikey).c_str(), ct.data(), ct.size());
        return Napi::String::New(env, (const char*)pt.data(), pt.size());
    } catch (const std::exception& e) {
        throw Napi::Error::New(env, e.what());
    }
}
*/

// std::vector<uint8_t> sign(const std::string& msg, const std::string& pem_pkey, int kt);
Napi::Value sign(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    try {
        auto msg = info[0].As<Buffer>();
        auto pem_pkey = info[1].As<Napi::String>(); // sth like -----BEGIN CERTIFICATE-----....
        auto kt = info[2].As<Napi::Number>();
        std::string msg_str(reinterpret_cast<const char*>(msg.Data()), msg.Length());
        auto sig = pl::sign(msg_str, pem_pkey, kt); // automaticall convert to std::string expected!   
        return Buffer::Copy(info.Env(), sig.data(), sig.size());
    } catch (const std::exception& e) {
        throw Napi::Error::New(env, e.what());
    }
}

// bool verify(const std::string& msg, const std::string& sig, const std::string &pem_cert, int kt);
Napi::Value verify(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    Napi::HandleScope scope(env);

    try {
        auto msg = info[0].As<Buffer>();
        auto sig = info[1].As<Buffer>();
        auto pem_cert = info[2].As<Napi::String>();
        auto kt = info[3].As<Napi::Number>();
        std::string msg_str(reinterpret_cast<const char*>(msg.Data()), msg.Length());
        std::string sig_str(reinterpret_cast<const char*>(sig.Data()), sig.Length());
        auto tf = pl::verify(msg_str, sig_str, pem_cert, kt); // automaticall convert to std::string expected!
        return Napi::Boolean::New(env, tf);
    } catch (const std::exception& e) {
        throw Napi::Error::New(env, e.what());
    }
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("sign", Napi::Function::New(env, sign));
    exports.Set("verify", Napi::Function::New(env, verify));
    return exports;
}

NODE_API_MODULE(signer, Init)
