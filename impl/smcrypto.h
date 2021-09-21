#include <vector>

namespace pl {
constexpr int RSA = 0;
constexpr int EC  = 1;
constexpr int SM  = 2;

// For msg and sig, we actually expect Uint8Array from javascript
// pem_key and pem_cert are expected to be js string
std::vector<uint8_t> sign(const std::string& msg, const std::string& pem_pkey, int kt);
bool verify(const std::string& msg, const std::string& sig, const std::string &pem_cert, int kt);

}  // namespace pl
