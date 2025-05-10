#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <libssh/server.h>
#include <chrono>
#include <iomanip>
#include <getopt.h>

const char *bindaddr = "localhost";
const char *rsa_key = "server_rsa_key"; // make sure this key file exists
const char *received_file = "received_file";
int port = 4096;

int buff_size = 16384 * 4; // 16KB

const char *user = "amd";
const char *password = "amd@123";
const char *local_file = "file.txt";
const char *host = "localhost";

#define BYTES_TO_MB(x) ((float)(x) / (1024 * 1024))
#define BYTES_TO_MBPS(bytes, millisecs) ((float)(bytes) / (1024 * 1024) / ((float)(millisecs) / 1000))

void cleanup_client(FILE *fp, ssh_channel channel, ssh_session session)
{
    if (fp)
        fclose(fp);
    if (channel)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
    if (session)
    {
        ssh_disconnect(session);
        ssh_free(session);
    }
}

void cleanup_server(FILE *fp, ssh_channel channel, ssh_session session, ssh_bind sshbind)
{
    if (fp)
    {
        fclose(fp);
        std::cout << "File closed" << std::endl;
    }
    if (channel)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        std::cout << "Channel closed" << std::endl;
    }
    if (session)
    {
        ssh_disconnect(session);
        ssh_free(session);
        std::cout << "Session closed" << std::endl;
    }
    if (sshbind)
    {
        ssh_bind_free(sshbind);
        std::cout << "SSH bind free" << std::endl;
    }
    std::cout << "Cleanup done" << std::endl;
}

/* functions for AEAD Ciphers */
int encrypt_aes_aead_openssl(const uint8_t *plaintext, int plaintext_len,
                             const uint8_t *aad, int aad_len,
                             const uint8_t *key, uint8_t *iv,
                             std::vector<uint8_t> &ciphertext,
                             uint8_t *tag);

int decrypt_aes_aead_openssl(const uint8_t *ciphertext, int ciphertext_len,
                             const uint8_t *aad, int aad_len,
                             const uint8_t *tag,
                             const uint8_t *key, const uint8_t *iv,
                             std::vector<uint8_t> &plaintext);

int encrypt_aes_aead_alcp(const uint8_t *plaintext, int plaintext_len,
                          const uint8_t *aad, int aad_len,
                          const uint8_t *key, uint8_t *iv,
                          std::vector<uint8_t> &ciphertext,
                          uint8_t *tag);

int decrypt_aes_aead_alcp(const uint8_t *ciphertext, int ciphertext_len,
                          const uint8_t *aad, int aad_len,
                          uint8_t *tag,
                          const uint8_t *key, const uint8_t *iv,
                          std::vector<uint8_t> &plaintext);

/* for generic (non-AEAD Ciphers)*/
int decrypt_aes_alcp(const uint8_t *ciphertext, int ciphertext_len,
                     const uint8_t *key, const uint8_t *iv,
                     std::vector<uint8_t> &plaintext);

int encrypt_aes_alcp(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *iv, std::vector<uint8_t> &ciphertext);

int encrypt_aes_openssl(const uint8_t *plaintext, int plaintext_len,
                        const uint8_t *key, uint8_t *iv,
                        std::vector<uint8_t> &ciphertext);
int decrypt_aes_openssl(const uint8_t *ciphertext, int ciphertext_len,
                        const uint8_t *key, const uint8_t *iv,
                        std::vector<uint8_t> &plaintext);

static uint8_t aad[] = {
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
};

// static uint8_t iv[] = {
//     0x0,
//     0x1,
//     0x2,
//     0x3,
//     0x4,
//     0x5,
//     0x6,
//     0x7,
//     0x8,
//     0x9,
//     0xa,
//     0xb,
// };

// static uint8_t iv_128[] = {
//     0xf,
//     0xe,
//     0xd,
//     0xc,
//     0xb,
//     0xa,
//     0x9,
//     0x8,
//     0x7,
//     0x6,
//     0x5,
//     0x4,
//     0x3,
//     0x2,
//     0x1,
//     0x0,
// };

/* 128 bit key */
// static uint8_t key_128[] = {
//     0x0,
//     0x1,
//     0x2,
//     0x3,
//     0x4,
//     0x5,
//     0x6,
//     0x7,
//     0x8,
//     0x9,
//     0xa,
//     0xb,
//     0xc,
//     0xd,
//     0xe,
//     0xf,
// };

// 256-bit key
static uint8_t key_256[] = {
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
};
