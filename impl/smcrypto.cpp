// Standalone file using Botan to implement sign/verify for generating WASM.

#include <botan/x509cert.h>
#include <botan/x509_key.h>
#include <botan/data_src.h>
#include <botan/pubkey.h>
#include <botan/hash.h>
#include <botan/pkcs8.h>
#include <botan/sm2.h>
#include <botan/ber_dec.h>
#include <botan/pk_algs.h>
#include <botan/base64.h>
#include <botan/auto_rng.h>
// #include <botan/ecies.h>

#include "smcrypto.h"

// #include <iostream>

namespace pl {

#define Throw(fmt, ...) {char err_msg[BUF_SIZE]; snprintf(err_msg, sizeof(err_msg), fmt, ##__VA_ARGS__); throw std::runtime_error(err_msg);}

constexpr size_t BUF_SIZE = 1024;  // used in Throw

std::unique_ptr<Botan::Public_Key> load_pubkey(const std::vector<uint8_t>& pubkey, bool isSM2)
// vkey64: base64 encoded pem-format public key
{
    Botan::DataSource_Memory src(pubkey);

    if (isSM2) {
        Botan::AlgorithmIdentifier alg_id;
        std::vector<uint8_t> key_bits;
        Botan::BER_Decoder(src)
            .start_cons(Botan::SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, Botan::BIT_STRING)
        .end_cons();
        return std::unique_ptr<Botan::Public_Key>(new Botan::SM2_PublicKey(alg_id, key_bits));
    }
    
    return std::unique_ptr<Botan::Public_Key>(Botan::X509::load_key(src));  // RSA or ECDSA
}

std::unique_ptr<Botan::Private_Key> load_prikey(const Botan::secure_vector<uint8_t>& prikey, bool isSM2)
// skey64: base64 encoded pkcs8 format private key
{
    Botan::DataSource_Memory src(prikey);

    if (isSM2) {
        Botan::AlgorithmIdentifier alg_id;
        Botan::secure_vector<uint8_t> key;

        while (!src.end_of_data()) {
            uint8_t b;
            size_t read = src.read_byte(b);
            if (read)
                key.push_back(b);
        }

        Botan::BER_Decoder(key)
            .start_cons(Botan::SEQUENCE)
            .decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
            .decode(alg_id)
            .decode(key, Botan::OCTET_STRING)
            .discard_remaining()
        .end_cons();

        return std::unique_ptr<Botan::Private_Key>(new Botan::SM2_PrivateKey(alg_id, key));
    }

    return Botan::PKCS8::load_key(src); // this version of load_key directly return a unique_ptr
}

std::vector<uint8_t> sign(const std::string& msg, const std::string& pem_pkey, int kt)
{
    const char* s = pem_pkey.data();
    const char* e = pem_pkey.data() + pem_pkey.length();
    if (*s == '-') {
        s += 18;  // skip sth like -.*BEGIN PRIVATE KEY-.*; 18 just a rough but reliable estimate
        while (*s != '-') ++s;   // continue skip 
        while (*s == '-') ++s;   // skip lefover '-'s 
        e = s;
        while (*e != '-') ++e;  // skip main part
    }

    auto pkey = Botan::base64_decode(s, e-s, true);
    auto pri_key = load_prikey(pkey, kt == SM);

    std::unique_ptr<Botan::PK_Signer> signer;
    Botan::AutoSeeded_RNG rng;
    if (kt == SM)
        signer.reset(new Botan::PK_Signer(*pri_key, rng, "1234567812345678,SM3", Botan::DER_SEQUENCE));
    else if (kt == RSA)
        signer.reset(new Botan::PK_Signer(*pri_key, rng, "EMSA3(SHA-256)"));
    else if (kt == EC)
        signer.reset(new Botan::PK_Signer(*pri_key, rng, "EMSA1(SHA-256)", Botan::DER_SEQUENCE));
    else
        Throw("Wrong KeyType: %d", kt);

    return signer->sign_message(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), rng);
}

bool verify(const std::string& msg, const std::string& sig, const std::string &pem_cert, int kt)
{
    Botan::DataSource_Memory src(pem_cert);
    Botan::X509_Certificate cert(src);
    auto pub_key = load_pubkey(cert.subject_public_key_info(), kt == SM);

    std::unique_ptr<Botan::PK_Verifier> verifier;
    if (kt == SM)
        verifier.reset(new Botan::PK_Verifier(*pub_key, "1234567812345678,SM3", Botan::DER_SEQUENCE));
    else if (kt == RSA)
        verifier.reset(new Botan::PK_Verifier(*pub_key, "EMSA3(SHA-256)"));
    else if (kt == EC)
        verifier.reset(new Botan::PK_Verifier(*pub_key, "EMSA1(SHA-256)", Botan::DER_SEQUENCE));
    else
        Throw("Wrong KeyType: %d", kt);
    
    return verifier->verify_message(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), 
        reinterpret_cast<const uint8_t*>(sig.data()), sig.size());          
}

/*
std::tuple<std::string, std::string> gen_key_pair(const std::string& algo, const std::string& params)
{
    Botan::AutoSeeded_RNG rng;
    auto key = Botan::create_private_key(algo, rng, params);
    if (!key)  Throw("gen_key_pair: failed");
    return std::make_tuple(Botan::PKCS8::PEM_encode(*key), Botan::X509::PEM_encode(*key));
}

class Fixed_RNG final : public Botan::RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return false; }

      bool accepts_input() const override { return false; }

      void clear() override {}

      void randomize(uint8_t buf[], size_t sz) override
         {
             memset(buf, 'x', sz);
         }

      void add_entropy(const uint8_t[], size_t) override {}

      std::string name() const override { return "Fixed_RNG"; }
   };

std::string smencrypt(const char* pkey64, const std::string& msg)
// Encrypt msg with base64 encoded public key pkey64 and return the encrypted message in base64 format.
{
    auto k_ptr = load_pubkey(pkey64, true);

    //Botan::AutoSeeded_RNG rng;
    Fixed_RNG rng;
    Botan::PK_Encryptor_EME enc(*k_ptr, rng, "SM3", "");  // padding: SM3, provider: ""
    auto ct = enc.encrypt(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), rng);
    return Botan::base64_encode(ct);
}

std::vector<uint8_t> smdecrypt(const char* pkey64, const char* ct64, size_t ct_len)  // ct64: base64 based ciphertext
// Decrypt base64 encoded msg with base64 encoded pcks8-format private key pkey64 and return the decrypted message.
{
    auto k_ptr = load_prikey(pkey64, true);

    //Botan::AutoSeeded_RNG rng;
    Fixed_RNG rng;
    Botan::PK_Decryptor_EME dec(*k_ptr, rng, "SM3", "");
    auto ct = Botan::base64_decode(ct64, ct_len);
    auto pt = dec.decrypt(ct);
    return Botan::unlock(pt);
}

std::string ecencrypt(const char* pkey64, const uint8_t* msg, size_t msg_len)
// Encrypt msg with base64 encoded public key pkey64 and return the encrypted message in base64 format.
{
    auto k_ptr = load_pubkey(pkey64, false);

    Botan::AutoSeeded_RNG rng;
    Botan::ECDH_PrivateKey private_key(rng, Botan::EC_Group("secp256r1"));
    Botan::ECIES_System_Params params(private_key.domain(), 
        "KDF1-18033(SHA-256)", "AES-128/CBC", 16, "HMAC(SHA-1)", 20,
        Botan::PointGFp::Compression_Type::COMPRESSED, 
        Botan::ECIES_Flags::SINGLE_HASH_MODE | Botan::ECIES_Flags::COFACTOR_MODE);
    Botan::ECIES_Encryptor enc(private_key, params, rng);
    enc.set_other_key(reinterpret_cast<Botan::EC_PublicKey*>(k_ptr.get())->public_point());
    auto ret = enc.encrypt(msg, msg_len, rng);
    return Botan::base64_encode(ret);
}

std::vector<uint8_t> ecdecrypt(const char* pkey64, const char* ct64, size_t ct_len)  // ct64: base64 based ciphertext
// Decrypt base64 encoded msg with base64 encoded pcks8-format private key pkey64 and return the decrypted message.
{
    auto k_ptr = load_prikey(pkey64, false);
    auto& pk = *reinterpret_cast<Botan::EC_PrivateKey*>(k_ptr.get());
    Botan::AutoSeeded_RNG rng;
    Botan::ECIES_System_Params params(pk.domain(), 
        "KDF2(SHA-256)", "AES-128/CBC", 16, "HMAC(SHA-1)", 20,
        Botan::PointGFp::Compression_Type::UNCOMPRESSED, 
        Botan::ECIES_Flags::SINGLE_HASH_MODE | Botan::ECIES_Flags::COFACTOR_MODE);
    Botan::ECIES_Decryptor dec(Botan::ECDH_PrivateKey(pk.algorithm_identifier(), pk.private_key_bits()), params, rng);
    auto ct = Botan::base64_decode(ct64, ct_len);
    dec.set_initialization_vector(Botan::OctetString("000102030405060708090a0b0c0d0e0f"));
    dec.set_label(std::string(8, 0));
    auto pt = dec.decrypt(ct);
    return Botan::unlock(pt);
}
*/
}  // namespace pl

/*  Test sign/verify with ECDSA
int main() {
    const char* cert = "-----BEGIN CERTIFICATE-----\n"
                        "MIICHzCCAcWgAwIBAgIQQQvetD3aAIyE9iH+wdlKNjAKBggqhkjOPQQDAjB3MQsw"
                        "CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy"
                        "YW5jaXNjbzEbMBkGA1UEChMSYmxvY2tjaGFpbi5jY2IuY29tMR4wHAYDVQQDExVj"
                        "YS5ibG9ja2NoYWluLmNjYi5jb20wHhcNMjEwOTEwMDQ1NDAwWhcNMzEwOTA4MDQ1"
                        "NDAwWjBdMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UE"
                        "BxMNU2FuIEZyYW5jaXNjbzEhMB8GA1UEAxMYcGVlcjAuYmxvY2tjaGFpbi5jY2Iu"
                        "Y29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEei5rLMYX2EO5HRet+BuGwhFV"
                        "tL3yKeM+SfmIIJ6WgmAn3zU6tsunGEbj9SunOldpAyOGbGJVadZe6AgHLhhO3aNN"
                        "MEswDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAg1ozl"
                        "LF6RZWn8hK1L1FyJ4WISdw5PNIO1/1MGaHKCLlswCgYIKoZIzj0EAwIDSAAwRQIh"
                        "AOw3GSt9x6Ol0qob6fbLzVX+74B/C9SyZQGvqfLSDWnGAiB58iQaC4+AK3CfRHWP"
                        "cAAfg+HgyI+A8x2uh8z26lOcOw==\n"
                        "-----END CERTIFICATE-----";
    const char* pkey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglNW80FMz+HOtcYA4"
                       "m6hI2apEEHGzVBPt4g1n+k1O3A+hRANCAAR6LmssxhfYQ7kdF634G4bCEVW0vfIp"
                       "4z5J+YggnpaCYCffNTq2y6cYRuP1K6c6V2kDI4ZsYlVp1l7oCAcuGE7d";
    const char* msg = "hello, world";
    const char* msg1 = "Hello, world";

    auto sig = sign(std::vector<uint8_t>((uint8_t*)msg, (uint8_t*)msg+strlen(msg)), pkey);
    auto tf = verify(std::vector<uint8_t>((uint8_t*)msg1, (uint8_t*)msg1+strlen(msg1)), sig, cert);
    std::cout << "Result: " << tf << '\n';
    tf = verify(std::vector<uint8_t>((uint8_t*)msg, (uint8_t*)msg+strlen(msg)), sig, cert);
    std::cout << "Result: " << tf << '\n';
}
*/

/* Test ECIES for SM2
int main(int argc, char** argv)
{
    const char* msg = "hello, world";

    // Test sm
    const char* prikey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnfE3KgS4+k1Lu6TRsGB35dUX56oU3byBvTvLC8NCyWyhRANCAAQWelexaZLOAL9oxbglbwGv8OZJzp++Y2PY9szzINKbxV6TZlNr2bO8EW+/KfrTAm8ahQaB+eVsZ4mjX3ZRCwmN";
    const char* pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFnpXsWmSzgC/aMW4JW8Br/DmSc6fvmNj2PbM8yDSm8Vek2ZTa9mzvBFvvyn60wJvGoUGgfnlbGeJo192UQsJjQ==";

    auto ct = pl::smencrypt(pubkey, (const uint8_t*)msg, strlen(msg));
    std::cout << "SM Ciphertext: " << ct << '\n';
    auto pt = pl::smdecrypt(prikey, ct.data(), ct.size());

    std::string s(pt.begin(), pt.end());
    std::cout << s << '\n';


    // Test ECIES
    pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZf74TUNL7q9L5AXoKzKepcoTcsi3"
             "dLSHR+cWzm8K1CbFrDrylzx+LXmuZivPmFs9/hTcAhLce7SWxJK4cr3fPg==";
    prikey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg30MrCAOSC9LcvT82"
             "aRgsKkzAV4wzDLI6TpeLjujc3kuhRANCAARl/vhNQ0vur0vkBegrMp6lyhNyyLd0"
             "tIdH5xbObwrUJsWsOvKXPH4tea5mK8+YWz3+FNwCEtx7tJbEkrhyvd8+";
        
    // ct = pl::ecencrypt(pubkey, (const uint8_t*)msg, strlen(msg));
    // std::cout << "EC Ciphertext: " << ct << '\n';
    //// This is result from eccrypt.ts. Not done yet. Need to compare with eccrypt.ts step by step.
    const char* ct1 = "BBnu6uLCgqilq07QYitEo49LMM1QR8mYdpAG5I6tNOZhIXbDXMHZSI3RjfEC257vS2K4cpWn965eUQmboh2FeB2XP6v8hI/ksFnKH8tlHfhuZCFYfu56/Nv1WFPAtKJof9HfnbtDg9mAnu0OPCPnWa9MXSpI";
    pt = pl::ecdecrypt(prikey, ct1, strlen(ct1));

    std::string s1(pt.begin(), pt.end());
    std::cout << s1 << '\n'; // This is not an error
}
*/