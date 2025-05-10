#include "key_exchange.hh"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <cstring>

// Store the private key globally (not ideal, but simple for demo)
EVP_PKEY *private_key = nullptr;

std::vector<uint8_t> generate_ecdh_keypair()
{
    std::vector<uint8_t> public_key_bytes;

    // Create a context for parameter generation
    EVP_PKEY_CTX *param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!param_ctx)
    {
        std::cerr << "Failed to create EC parameter context" << std::endl;
        return public_key_bytes;
    }

    // Initialize parameter generation
    if (EVP_PKEY_paramgen_init(param_ctx) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        std::cerr << "Failed to initialize parameter generation" << std::endl;
        return public_key_bytes;
    }

    // Use P-256 curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        std::cerr << "Failed to set curve" << std::endl;
        return public_key_bytes;
    }

    // Generate parameters
    EVP_PKEY *params = nullptr;
    if (EVP_PKEY_paramgen(param_ctx, &params) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        std::cerr << "Failed to generate parameters" << std::endl;
        return public_key_bytes;
    }

    // Create context for key generation
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(param_ctx);

    if (!key_ctx)
    {
        std::cerr << "Failed to create key generation context" << std::endl;
        return public_key_bytes;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        std::cerr << "Failed to initialize key generation" << std::endl;
        return public_key_bytes;
    }

    // Generate key pair
    if (EVP_PKEY_keygen(key_ctx, &private_key) <= 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        std::cerr << "Failed to generate key pair" << std::endl;
        return public_key_bytes;
    }

    EVP_PKEY_CTX_free(key_ctx);

    // Extract the public key bytes
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        std::cerr << "Failed to create BIO" << std::endl;
        return public_key_bytes;
    }

    if (i2d_PUBKEY_bio(bio, private_key) <= 0)
    {
        BIO_free(bio);
        std::cerr << "Failed to serialize public key" << std::endl;
        return public_key_bytes;
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    public_key_bytes.resize(bptr->length);
    std::memcpy(public_key_bytes.data(), bptr->data, bptr->length);
    BIO_free(bio);

    return public_key_bytes;
}

bool compute_shared_secret(const std::vector<uint8_t> &peer_public_key,
                           std::vector<uint8_t> &shared_key,
                           std::vector<uint8_t> &iv)
{
    if (!private_key)
    {
        std::cerr << "Private key not initialized" << std::endl;
        return false;
    }

    // Deserialize peer's public key
    const unsigned char *p = peer_public_key.data();
    EVP_PKEY *peer_key = d2i_PUBKEY(nullptr, &p, peer_public_key.size());
    if (!peer_key)
    {
        std::cerr << "Failed to deserialize peer's public key" << std::endl;
        return false;
    }

    // Create a context for deriving the shared secret
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx)
    {
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to create context for shared secret derivation" << std::endl;
        return false;
    }

    // Initialize derivation
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to initialize derivation" << std::endl;
        return false;
    }

    // Set peer's public key
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to set peer key" << std::endl;
        return false;
    }

    // Determine buffer length for shared secret
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to determine secret length" << std::endl;
        return false;
    }

    // Derive the shared secret
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to derive shared secret" << std::endl;
        return false;
    }

    // Use HKDF to derive key and IV
    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!hkdf_ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to create HKDF context" << std::endl;
        return false;
    }

    if (EVP_PKEY_derive_init(hkdf_ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, (const unsigned char *)"SCP_SALT", 8) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, secret.data(), secret.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (const unsigned char *)"SCP_KEY_IV", 10) <= 0)
    {
        EVP_PKEY_CTX_free(hkdf_ctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to set up HKDF" << std::endl;
        return false;
    }

    // Generate 44 bytes (32 for key, 12 for IV)
    unsigned char derived[44];
    size_t derived_len = sizeof(derived);
    if (EVP_PKEY_derive(hkdf_ctx, derived, &derived_len) <= 0)
    {
        EVP_PKEY_CTX_free(hkdf_ctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        std::cerr << "Failed to derive key material" << std::endl;
        return false;
    }

    // Split into key and IV
    shared_key.assign(derived, derived + 32);
    iv.assign(derived + 32, derived + 44);

    // Clean up
    EVP_PKEY_CTX_free(hkdf_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);

    return true;
}
