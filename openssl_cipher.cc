#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <iostream>

/**
 * Encrypt data using AES-GCM
 *
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad Additional authenticated data (optional)
 * @param aad_len Length of AAD
 * @param key 256-bit key (32 bytes)
 * @param iv Initialization vector (12 bytes recommended for GCM)
 * @param ciphertext Output buffer for encrypted data
 * @param tag Output buffer for authentication tag (16 bytes)
 * @return Length of ciphertext or -1 on error
 */
int encrypt_aes_gcm_openssl(const uint8_t *plaintext, int plaintext_len,
                            const uint8_t *aad, int aad_len,
                            const uint8_t *key, uint8_t *iv,
                            std::vector<uint8_t> &ciphertext,
                            uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        std::cout << "Error creating context" << std::endl;
        return -1;
    }
    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        std::cout << "Error initializing encryption" << std::endl;
        return -1;
    }

    // Set IV length (12 bytes is recommended for GCM)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    {
        std::cout << "Error setting IV length" << std::endl;
        return -1;
    }

    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        std::cout << "Error initializing key and IV" << std::endl;
        return -1;
    }

    // Provide AAD data if available
    if (aad && aad_len > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            std::cout << "Error providing AAD" << std::endl;
            return -1;
        }
    }

    // Allocate memory for ciphertext
    ciphertext.resize(plaintext_len);

    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len))
    {
        std::cout << "Error encrypting data" << std::endl;
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        std::cout << "Error finalizing encryption" << std::endl;
        return -1;
    }
    ciphertext_len += len;

    // Get the tag (16 bytes is the default for GCM)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        std::cout << "Error getting tag" << std::endl;
        return -1;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Encryption successful, cipher text len " << ciphertext_len << std::endl;
    return ciphertext_len;
}

/**
 * Decrypt data using AES-GCM
 *
 * @param ciphertext Data to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param aad Additional authenticated data (optional)
 * @param aad_len Length of AAD
 * @param tag Authentication tag (16 bytes)
 * @param key 256-bit key (32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param plaintext Output buffer for decrypted data
 * @return Length of plaintext or -1 on error
 */
int decrypt_aes_gcm_openssl(const uint8_t *ciphertext, int ciphertext_len,
                            const uint8_t *aad, int aad_len,
                            const uint8_t *tag,
                            const uint8_t *key, const uint8_t *iv,
                            std::vector<uint8_t> &plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        std::cout << "Error creating context" << std::endl;
        return -1;
    }
    std::cout << "Decrypt Context created" << std::endl;

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        std::cout << "Error initializing decryption" << std::endl;
        return -1;
    }
    std::cout << "Decryption initialized" << std::endl;

    // Set IV length (12 bytes is recommended for GCM)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    {
        std::cout << "Error setting IV length" << std::endl;
        return -1;
    }
    std::cout << "IV length set" << std::endl;

    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        std::cout << "Error initializing key and IV" << std::endl;
        return -1;
    }
    std::cout << "Key and IV initialized" << std::endl;

    // Provide AAD data if available
    if (aad && aad_len > 0)
    {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            std::cout << "Error providing AAD" << std::endl;
            return -1;
        }
    }
    std::cout << "AAD provided" << std::endl;

    // Allocate memory for plaintext
    plaintext.resize(ciphertext_len);

    // Decrypt ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len))
    {
        std::cout << "Error decrypting data" << std::endl;
        return -1;
    }
    std::cout << "Data decrypted, length decrypted " << len << std::endl;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx,
                                 EVP_CTRL_AEAD_SET_TAG,
                                 16,
                                 (void *)tag))
    {
        std::cout << "Error: Tag Setting Failed" << std::endl;
        return -1;
    }
    std::cout << "Tag set" << std::endl;

    // Finalize decryption. Verify the tag.
    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1)
    {
        std::cout << "Error finalizing decryption" << std::endl;
        // Authentication failed
        return -1;
    }
    std::cout << "Decryption finalized" << std::endl;

    // Authentication succeeded
    plaintext_len += len;

    std::cout << "Decryption successful, plain text len " << plaintext_len << std::endl;
    return plaintext_len;
}
