#include "custom_scp.hh"
#include "key_exchange.hh"

/* FIXME: make this parameterized via cmake*/
/* selecting lib also should be parameterized */
#define ENABLE_LOGGING 0

int main(int argc, char *argv[])
{
    int opt;
    std::string lib_name;
    bool verbose = false;

    while ((opt = getopt(argc, argv, "vl:")) != -1)
    {
        switch (opt)
        {
        case 'v':
            verbose = true;
            break;
        case 'l':
            lib_name = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-v] -l <library>\n", argv[0]);
            fprintf(stderr, "Library options: alcp, openssl\n");
            fprintf(stderr, "-v: Enable verbose output\n");
            return 1;
        }
    }

    if (lib_name.empty())
    {
        fprintf(stderr, "Library type is required\n");
        fprintf(stderr, "Usage: %s [-v] -l <library>\n", argv[0]);
        fprintf(stderr, "Library options: alcp, openssl\n");
        return 1;
    }

    if (lib_name != "alcp" && lib_name != "openssl")
    {
        fprintf(stderr, "Invalid library: %s\n", lib_name.c_str());
        fprintf(stderr, "Library options: alcp, openssl\n");
        return 1;
    }

    if (verbose)
    {
        std::cout << "Verbose mode enabled" << std::endl;
        std::cout << "Using library: " << lib_name << std::endl;
    }

    int rc;
    ssh_bind sshbind = ssh_bind_new();
    ssh_message message = NULL;
    ssh_session session = NULL;
    ssh_channel channel = NULL;

    FILE *fp = NULL;

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, rsa_key);

    if (ssh_bind_listen(sshbind) < 0)
    {
        fprintf(stderr, "Error listening: %s\n", ssh_get_error(sshbind));
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    std::cout << "Server listening on " << bindaddr << ":" << port << "..." << std::endl;

    session = ssh_new();
    if (ssh_bind_accept(sshbind, session) != SSH_OK)
    {
        fprintf(stderr, "Error accepting connection: %s\n", ssh_get_error(sshbind));
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    if (verbose)
    {
        std::cout << "Connection accepted" << std::endl;
    }

    if (ssh_handle_key_exchange(session))
    {
        fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Key exchange successful" << std::endl;
    }

    // auto-accept any authentication request
    int auth = 0;
    while (!auth)
    {
        if (verbose)
            std::cout << "Inside authentication check loop" << std::endl;
        message = ssh_message_get(session);
        if (message == NULL)
        {
            if (verbose)
                std::cout << "Message is null" << std::endl;
            break;
        }
        if (verbose)
            std::cout << "Msg received from session" << std::endl;

        int msg_type = ssh_message_type(message);
        if (verbose)
            std::cout << "Message type: " << msg_type << std::endl;

        if (msg_type == SSH_REQUEST_SERVICE)
        {
            // Accept any service request
            const char *service = ssh_message_service_service(message);
            if (verbose)
                std::cout << "Requested service: " << (service ? service : "NULL") << std::endl;
            ssh_message_service_reply_success(message);
        }
        else if (msg_type == SSH_REQUEST_AUTH)
        {
            // Auto-accept any authentication request without checking credentials
            if (verbose)
                std::cout << "Auth request - auto-accepting" << std::endl;
            ssh_message_auth_reply_success(message, 0);
            auth = 1; // Set auth to success immediately
        }
        else
        {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }
    if (verbose)
        std::cout << "Authenticated, waiting for client channel requests" << std::endl;

    int channel_established = 0;
    while (!channel_established)
    {
        message = ssh_message_get(session);
        if (message == NULL)
        {
            if (verbose)
                std::cout << "Message is null while waiting for channel" << std::endl;
            break;
        }
        int msg_type = ssh_message_type(message);
        if (verbose)
            std::cout << "Message type: " << msg_type << std::endl;
        if (msg_type == SSH_REQUEST_CHANNEL_OPEN)
        {
            if (verbose)
                std::cout << "Channel open request received" << std::endl;
            if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
            {
                if (verbose)
                    std::cout << "Session channel requested, accepting" << std::endl;
                channel = ssh_message_channel_request_open_reply_accept(message);
                if (channel != NULL)
                {
                    channel_established = 1;
                    if (verbose)
                        std::cout << "Channel established" << std::endl;
                }
                else
                {
                    std::cout << "Failed to accept channel: " << ssh_get_error(session) << std::endl;
                }
            }
            else
            {
                std::cout << "Rejecting non-session channel request" << std::endl;
                ssh_message_reply_default(message);
            }
        }
        else if (msg_type == SSH_REQUEST_CHANNEL)
        {
            if (verbose)
                std::cout << "Channel request received" << std::endl;
            int req_type = ssh_message_subtype(message);
            if (verbose)
                std::cout << "Channel request type: " << req_type << std::endl;

            // Handle specific channel requests like exec, shell, subsystem
            if (req_type == SSH_CHANNEL_REQUEST_EXEC)
            {
                if (verbose)
                    std::cout << "Channel req type received is REQUEST_EXEC" << std::endl;
                const char *command = ssh_message_channel_request_command(message);
                if (verbose)
                    std::cout << "Exec request: " << (command ? command : "NULL") << std::endl;

                // Check if it's an SCP command
                if (command && strncmp(command, "scp", 3) == 0)
                {
                    ssh_message_channel_request_reply_success(message);
                    if (verbose)
                        std::cout << "Accepted SCP exec request" << std::endl;
                }
                else
                {
                    ssh_message_reply_default(message);
                }
            }
            else
            {
                if (verbose)
                    std::cout << "Channel default reply" << std::endl;
                ssh_message_reply_default(message);
            }
        }
        else
        {
            if (verbose)
                std::cout << "Unexpected message type, ignoring" << std::endl;
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (!channel_established)
    {
        if (verbose)
            std::cout << "Failed to establish channel with client" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    /* just cross check if channel is open for data transfer */
    if (ssh_channel_is_open(channel))
    {
        if (verbose)
            std::cout << "Channel is open" << std::endl;
    }
    else
    {
        if (verbose)
            std::cout << "Channel is closed" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    /* key exchange part */
    // Receive client's public key size
    int nbytes;
    uint32_t client_key_size;
    if ((nbytes = ssh_channel_read(channel, &client_key_size, sizeof(client_key_size), 0)) != sizeof(client_key_size))
    {
        std::cerr << "Failed to receive client key size" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    client_key_size = ntohl(client_key_size);

    // Receive client's public key
    std::vector<uint8_t> client_public_key(client_key_size);
    if ((nbytes = ssh_channel_read(channel, client_public_key.data(), client_key_size, 0)) != (int)client_key_size)
    {
        std::cerr << "Failed to receive client public key" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Received client public key (" << client_key_size << " bytes)" << std::endl;
    }

    // Generate our key pair
    std::vector<uint8_t> our_public_key = generate_ecdh_keypair();
    if (our_public_key.empty())
    {
        std::cerr << "Failed to generate key pair" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Generated ECDH key pair" << std::endl;
    }

    // Send our public key size
    uint32_t key_size = htonl(our_public_key.size());
    if (ssh_channel_write(channel, &key_size, sizeof(key_size)) != sizeof(key_size))
    {
        std::cerr << "Failed to send key size" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    // Send our public key
    if (ssh_channel_write(channel, our_public_key.data(), our_public_key.size()) != (int)our_public_key.size())
    {
        std::cerr << "Failed to send public key" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Sent public key (" << our_public_key.size() << " bytes)" << std::endl;
    }

    // Compute shared secret
    std::vector<uint8_t> encryption_key, iv_vec;
    if (!compute_shared_secret(client_public_key, encryption_key, iv_vec))
    {
        std::cerr << "Failed to compute shared secret" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Computed shared secret and derived encryption keys" << std::endl;
    }

    /* print encryption key and iv */
    if (verbose)
    {
        std::cout << "Encryption key: ";
        for (int i = 0; i < 32; i++)
        {
            std::cout << std::hex << (int)encryption_key[i] << " ";
        }
        std::cout << std::endl;
        std::cout << "IV: ";
        for (int i = 0; i < 12; i++)
        {
            std::cout << std::hex << (int)iv_vec[i] << " ";
        }
        std::cout << std::endl;
    }
    // Copy the IV to the existing iv buffer for compatibility with current code
    // memcpy(iv, iv_vec.data(), 12);

    // Now use encryption_key and iv_vec instead of hardcoded values

    /* RECEIVING SIDE */
    if (verbose)
        std::cout << "Reading data from channel" << std::endl;
    // int nbytes;
    char buffer[buff_size];

    fp = fopen(received_file, "wb");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening output file\n");
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    if (verbose)
        std::cout << "File opened for writing" << std::endl;

    uint8_t tag_received[16];
    uint8_t tag_calculated[16];
    std::vector<uint8_t> decrypted_data{};

    /* in a loop, first read the tag, then the buffer */
    uint64_t total_bytes_received = 0;

    auto start_time = std::chrono::high_resolution_clock::now();
    auto last_update = start_time;

    int dec_len;

    while (1)
    {
#if ENABLE_AEAD
        nbytes = ssh_channel_read(channel, tag_received, sizeof(tag_received), 0);
        if (nbytes == 0)
        {
            /* FIXME: is this correct??? */
            std::cout << "End of file" << std::endl;
            break;
        }
        if (nbytes != 16)
        {
            std::cerr << "Failed to read tag from client" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
#endif

        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes == 0)
        {
            std::cout << "End of file" << std::endl;
            break;
        }

        if (nbytes < 0)
        {
            std::cerr << "Failed to read data" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
        /* call decrypt */
        /* FIXME: Make this parameterized, based on lib type (alcp / openssl / etc)*/
#if ENABLE_AEAD
        dec_len = decrypt_aes_aead_alcp((uint8_t *)buffer, nbytes, aad, 12, tag_calculated, key_256, iv, decrypted_data);
#else

        if (lib_name == "alcp")
        {
            dec_len = decrypt_aes_alcp((uint8_t *)buffer, nbytes, &encryption_key[0], &iv_vec[0], decrypted_data);
        }
        else if (lib_name == "openssl")
        {
            dec_len = decrypt_aes_openssl((uint8_t *)buffer, nbytes, &encryption_key[0], &iv_vec[0], decrypted_data);
        }
        else
        {
            std::cerr << "Invalid library name. Use 'alcp' or 'openssl'." << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }

#endif
        if (dec_len < 0)
        {
            std::cerr << "Decryption function failed" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
        fwrite(decrypted_data.data(), 1, dec_len, fp);
        // std::cout << "Successfully Decrpyted and wrote " << dec_len << " bytes" << std::endl;
        total_bytes_received += nbytes;
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_update);
        // Update speed approximately every second
        if (interval.count() >= 1000)
        {
            float speed = BYTES_TO_MBPS(total_bytes_received, duration.count());
            std::cout << "\rReceived: " << BYTES_TO_MB(total_bytes_received)
                      << " MB at " << std::fixed << std::setprecision(2)
                      << speed << " MB/s" << std::endl;
            last_update = current_time;
        }
        // std::cout << "Total bytes received so far: " << total_bytes_received << std::endl;

        /* compare tags for AEAD */
#if ENABLE_AEAD
        if (memcmp(tag_received, tag_calculated, 16) != 0)
        {
            /* print both tags */
            std::cout << "Tag received: ";
            for (int i = 0; i < 16; i++)
            {
                std::cout << std::hex << (int)tag_received[i] << " ";
            }
            std::cout << std::endl;
            std::cout << "Tag calculated: ";
            for (int i = 0; i < 16; i++)
            {
                std::cout << std::hex << (int)tag_calculated[i] << " ";
            }
            std::cout << std::endl;
            std::cerr << "Tag mismatch" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
        std::cout << "Tags match" << std::endl;
#endif
    }

    std::cout << "Total bytes received: " << total_bytes_received << std::endl;
    std::cout << "File received and saved: " << received_file << std::endl;
    cleanup_server(fp, channel, session, sshbind);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    float average_speed = BYTES_TO_MBPS(total_bytes_received, total_duration.count());

    std::cout << "Server: Library used: " << lib_name << std::endl;
    std::cout << "\nTransfer Summary:" << std::endl;
    std::cout << "Total received: " << total_bytes_received
              << " bytes (" << BYTES_TO_MB(total_bytes_received) << " MB)" << std::endl;
    std::cout << "Total time: " << std::fixed << std::setprecision(2)
              << total_duration.count() / 1000.0 << " seconds" << std::endl;
    std::cout << "Average speed: " << average_speed << " MB/s" << std::endl;
    std::cout << "Session closed" << std::endl;

    /* calculate sha256 checksum on the received file */
    /* calculate sha256 checksum on the received file */
    std::cout << "Calculating SHA-256 hash of received file..." << std::endl;

    // Initialize OpenSSL hash context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        std::cerr << "Error creating hash context" << std::endl;
        return -1;
    }

    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Initialize the hash context
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
    {
        std::cerr << "Error initializing hash context" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Open the file for reading
    FILE *hash_fp = fopen(received_file, "rb");
    if (!hash_fp)
    {
        std::cerr << "Error opening file for hash calculation" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Read file in chunks and update hash
    // unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), hash_fp)) > 0)
    {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read))
        {
            std::cerr << "Error updating hash" << std::endl;
            fclose(hash_fp);
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }

    // Finalize the hash calculation
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len))
    {
        std::cerr << "Error finalizing hash" << std::endl;
        fclose(hash_fp);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Close the file and free the hash context
    fclose(hash_fp);
    EVP_MD_CTX_free(mdctx);

    // Display the hash in hex format
    std::cout << "SHA-256: ";
    for (unsigned int i = 0; i < hash_len; i++)
    {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    return 0;
}
