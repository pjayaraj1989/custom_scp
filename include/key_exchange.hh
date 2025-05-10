#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include <vector>
#include <cstdint>

// Generate ECDH key pair and return serialized public key
std::vector<uint8_t> generate_ecdh_keypair();

// Compute shared secret using our private key and peer's public key
bool compute_shared_secret(const std::vector<uint8_t> &peer_public_key,
                           std::vector<uint8_t> &shared_key,
                           std::vector<uint8_t> &iv);

#endif // KEY_EXCHANGE_H
