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

const char *bindaddr = "localhost";
const char *rsa_key = "server_rsa_key"; // make sure this key file exists
const char *received_file = "received_file";
int port = 8443;

const char *user = "amd";
const char *password = "amd@123";
const char *local_file = "file.txt";
const char *host = "localhost";

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
    if (sshbind)
    {
        ssh_bind_free(sshbind);
    }
}

int encrypt_aes_gcm_openssl(const uint8_t *plaintext, int plaintext_len,
                            const uint8_t *aad, int aad_len,
                            const uint8_t *key, uint8_t *iv,
                            std::vector<uint8_t> &ciphertext,
                            uint8_t *tag);

int decrypt_aes_gcm_openssl(const uint8_t *ciphertext, int ciphertext_len,
                            const uint8_t *aad, int aad_len,
                            const uint8_t *tag,
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

static uint8_t iv[] = {
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
// 256-bit key
static uint8_t key[] = {
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
