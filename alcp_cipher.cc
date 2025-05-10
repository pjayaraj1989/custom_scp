#include "alcp/alcp.h"
#include <vector>
#include <ostream>
#include <iostream>

int encrypt_aes_alcp(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *iv, std::vector<uint8_t> &ciphertext)
{
    alc_error_t err;
    static alc_cipher_handle_t handle;

    handle.ch_context = malloc(alcp_cipher_context_size());
    if (!handle.ch_context)
    {
        std::cout << "Error: unable to allocate memory" << std::endl;
        return -1;
    }

    err = alcp_cipher_request(ALC_AES_MODE_CTR, 128, &handle);
    if (alcp_is_error(err))
    {
        free(handle.ch_context);
        std::cout << "Error: unable to request cipher" << std::endl;
        return -1;
    }

    // CBC init key
    err = alcp_cipher_init(&handle, key, 128, iv, 16);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to init key" << std::endl;
        return -1;
    }

    // Allocate memory for ciphertext
    ciphertext.resize(plaintext_len);

    // CBC encrypt
    err = alcp_cipher_encrypt(&handle, plaintext, ciphertext.data(), plaintext_len);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable encrypt" << std::endl;
        return -1;
    }
    return plaintext_len;
}

int decrypt_aes_alcp(const uint8_t *ciphertext, int ciphertext_len,
                     const uint8_t *key, const uint8_t *iv,
                     std::vector<uint8_t> &plaintext)
{
    alc_error_t err;
    static alc_cipher_handle_t handle;

    handle.ch_context = malloc(alcp_cipher_context_size());
    if (!handle.ch_context)
    {
        std::cout << "Error: unable to allocate memory" << std::endl;
        return -1;
    }

    err = alcp_cipher_request(ALC_AES_MODE_CTR, 128, &handle);
    if (alcp_is_error(err))
    {
        free(handle.ch_context);
        std::cout << "Error: unable to request cipher" << std::endl;
        return -1;
    }

    // CBC init key
    err = alcp_cipher_init(&handle, key, 128, iv, 16);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to init key" << std::endl;
        return -1;
    }

    // Allocate memory for plaintext
    plaintext.resize(ciphertext_len);

    // CBC decrypt
    err = alcp_cipher_decrypt(&handle, ciphertext, plaintext.data(), ciphertext_len);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable decrypt" << std::endl;
        return -1;
    }
    return ciphertext_len;
}

int encrypt_aes_aead_alcp(const uint8_t *plaintext, int plaintext_len,
                          const uint8_t *aad, int aad_len,
                          const uint8_t *key, uint8_t *iv,
                          std::vector<uint8_t> &ciphertext,
                          uint8_t *tag)
{
    alc_error_t err;
    static alc_cipher_handle_t handle;

    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!handle.ch_context)
    {
        std::cout << "Error: unable to allocate memory" << std::endl;
        return -1;
    }

    err = alcp_cipher_aead_request(ALC_AES_MODE_GCM, 256, &handle);
    if (alcp_is_error(err))
    {
        free(handle.ch_context);
        std::cout << "Error: unable to request cipher" << std::endl;
        return -1;
    }

    // gcm init key
    err = alcp_cipher_aead_init(&handle, key, 256, iv, 12);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to init key" << std::endl;
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, aad, 12);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to set AAD" << std::endl;
        return -1;
    }

    // Allocate memory for ciphertext
    ciphertext.resize(plaintext_len);

    // GCM encrypt
    err = alcp_cipher_aead_encrypt(&handle, plaintext, ciphertext.data(), plaintext_len);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable encrypt" << std::endl;
        return -1;
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tag, 16);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable getting tag" << std::endl;
        return -1;
    }

    return plaintext_len;
}

int decrypt_aes_aead_alcp(const uint8_t *ciphertext, int ciphertext_len,
                          const uint8_t *aad, int aad_len,
                          uint8_t *tag,
                          const uint8_t *key, const uint8_t *iv,
                          std::vector<uint8_t> &plaintext)
{
    alc_error_t err;
    static alc_cipher_handle_t handle;

    handle.ch_context = malloc(alcp_cipher_aead_context_size());
    if (!handle.ch_context)
    {
        std::cout << "Error: unable to allocate memory" << std::endl;
        return -1;
    }

    err = alcp_cipher_aead_request(ALC_AES_MODE_GCM, 256, &handle);
    if (alcp_is_error(err))
    {
        free(handle.ch_context);
        std::cout << "Error: unable to request cipher" << std::endl;
        return -1;
    }

    // gcm init key
    err = alcp_cipher_aead_init(&handle, key, 256, iv, 12);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to init key" << std::endl;
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, aad, 12);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to set AAD" << std::endl;
        return -1;
    }

    // Allocate memory for plaintext
    plaintext.resize(ciphertext_len);

    // GCM decrypt
    err = alcp_cipher_aead_decrypt(&handle, ciphertext, plaintext.data(), ciphertext_len);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable decrypt" << std::endl;
        return -1;
    }

    // Verify tag
    err = alcp_cipher_aead_get_tag(&handle, tag, 16);
    if (alcp_is_error(err))
    {
        std::cout << "Error: unable to get tag" << std::endl;
        return -1;
    }

    return ciphertext_len;
}
