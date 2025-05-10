#include "custom_scp.hh"
#include "key_exchange.hh"

/* FIXME: make this parameterized via cmake*/
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

    ssh_session my_ssh_session = NULL;
    ssh_channel channel = NULL;
    FILE *fp = NULL;
    int rc;
    char buffer[buff_size];
    int nbytes;

    // Create a new SSH session
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
    {
        std::cout << "Error creating SSH session" << std::endl;
        return EXIT_FAILURE;
    }

    // Set the server options
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

    if (verbose)
    {
        std::cout << "SSH options set: " << std::endl;
        std::cout << "Host: " << host << std::endl;
        std::cout << "User: " << user << std::endl;
        std::cout << "Port: " << port << std::endl;
    }

    // Connect to the server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to server: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        return -1;
    }
    if (verbose)
        std::cout << "Connected to server" << std::endl;

    // For the client side, add this function to use "none" authentication

    // After connecting to the server
    if (verbose)
        std::cout << "Connected to server, attempting 'none' authentication" << std::endl;

    // Try "none" authentication
    rc = ssh_userauth_none(my_ssh_session, NULL);
    if (rc != SSH_AUTH_SUCCESS)
    {
        std::cerr << "Error in none authentication: " << ssh_get_error(my_ssh_session) << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    if (verbose)
        std::cout << "Authentication successful (no password required)" << std::endl;

    // Authenticate with the server
    // password = getpass("Enter your password: ");
    // rc = ssh_userauth_password(my_ssh_session, NULL, password);
    // if (rc != SSH_AUTH_SUCCESS)
    // {
    //     fprintf(stderr, "Error authenticating with server: %s\n", ssh_get_error(my_ssh_session));
    //     ssh_disconnect(my_ssh_session);
    //     ssh_free(my_ssh_session);
    //     return -1;
    // }
    // std::cout << "Authenticated with server" << std::endl;

    // Open a new channel
    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL)
    {
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    if (verbose)
        std::cout << "Channel created" << std::endl;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    if (verbose)
        std::cout << "Channel session opened" << std::endl;

    // Open the file to be sent
    fp = fopen(local_file, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening file\n");
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    if (verbose)
        std::cout << "File opened" << std::endl;

    uint64_t total_bytes_sent = 0;
    uint8_t tag[16]; // Authentication tag
    uint8_t iv[12];  // Initialization vector

    int encrypted_len;

    // Add timing variables
    auto start_time = std::chrono::high_resolution_clock::now();
    auto last_update = start_time;

    /* key exchange */
    // Generate our key pair
    std::vector<uint8_t> our_public_key = generate_ecdh_keypair();
    if (our_public_key.empty())
    {
        std::cerr << "Failed to generate key pair" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Generated ECDH key pair" << std::endl;
    }

    // Send our public key size first
    uint32_t key_size = htonl(our_public_key.size());
    if (ssh_channel_write(channel, &key_size, sizeof(key_size)) != sizeof(key_size))
    {
        std::cerr << "Failed to send key size" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    if (verbose)
    {
        std::cout << "Sent public key size (" << our_public_key.size() << " bytes)" << std::endl;
    }

    // Send our public key
    if (ssh_channel_write(channel, our_public_key.data(), our_public_key.size()) != (int)our_public_key.size())
    {
        std::cerr << "Failed to send public key" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Sent public key (" << our_public_key.size() << " bytes)" << std::endl;
    }

    // Receive server's public key size
    uint32_t server_key_size;
    if (ssh_channel_read(channel, &server_key_size, sizeof(server_key_size), 0) != sizeof(server_key_size))
    {
        std::cerr << "Failed to receive server key size" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    server_key_size = ntohl(server_key_size);

    // Receive server's public key
    std::vector<uint8_t> server_public_key(server_key_size);
    if (ssh_channel_read(channel, server_public_key.data(), server_key_size, 0) != (int)server_key_size)
    {
        std::cerr << "Failed to receive server public key" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Received server public key (" << server_key_size << " bytes)" << std::endl;
    }

    // Compute shared secret
    std::vector<uint8_t> encryption_key, iv_vec;
    if (!compute_shared_secret(server_public_key, encryption_key, iv_vec))
    {
        std::cerr << "Failed to compute shared secret" << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }

    if (verbose)
    {
        std::cout << "Computed shared secret and derived encryption keys" << std::endl;
    }
    /* print encryption key and iv vector */
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
    // Now use encryption_key and iv_vec instead of hardcoded values
    // Copy the IV to the existing iv buffer for compatibility with current code
    // memcpy(iv, iv_vec.data(), 12);

    // Read the file and send its contents to the server
    if (verbose)
        std::cout << "Sending file " << local_file << " to server" << std::endl;
    while ((nbytes = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        // Prepare for encryption
        std::vector<uint8_t> encrypted_data{};
        // Encrypt the data chunk
        /* FIXME: this should be parameterized based on the encryption lib (openssl / alcp)*/
#if ENABLE_AEAD
        encrypted_len = encrypt_aes_aead_openssl(
            (uint8_t *)buffer, nbytes,
            aad, 12, // AAD
            key_256, iv,
            encrypted_data, tag);
        /* print tag calculated */
        if (verbose)
            std::cout << "Tag calculated at server side: ";
        for (int i = 0; i < 16; i++)
        {
            std::cout << std::hex << (int)tag[i] << " ";
        }
        std::cout << std::endl;
#else

        if (lib_name == "alcp")
        {
            encrypted_len = encrypt_aes_alcp(
                (uint8_t *)buffer, nbytes,
                &encryption_key[0], &iv_vec[0],
                encrypted_data);
        }
        else if (lib_name == "openssl")
        {
            encrypted_len = encrypt_aes_openssl(
                (uint8_t *)buffer, nbytes,
                &encryption_key[0], &iv_vec[0],
                encrypted_data);
        }
        else
        {
            std::cerr << "Invalid library name. Use 'alcp' or 'openssl'." << std::endl;
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
#endif

        if (encrypted_len < 0)
        {
            std::cerr << "Encryption failed" << std::endl;
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
        uint32_t enc_len = encrypted_len;

        /* first send the tag to server */
#if ENABLE_AEAD
        rc = ssh_channel_write(channel, tag, 16);
        if (rc < 0)
        {
            fprintf(stderr, "Error sending tag: %s\n", ssh_get_error(my_ssh_session));
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
#endif
        /* first send the IV to server */
        // rc = ssh_channel_write(channel, &iv_vec[0], 12);
        // if (rc < 0)
        // {
        //     fprintf(stderr, "Error sending IV: %s\n", ssh_get_error(my_ssh_session));
        //     cleanup_client(fp, channel, my_ssh_session);
        //     return -1;
        // }
        // if (verbose)
        //     std::cout << "IV sent to server" << std::endl;

        /* now send the enc flie data in chunkss*/
        rc = ssh_channel_write(channel, encrypted_data.data(), enc_len);

        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_update);

        // std::cout << "Sending " << enc_len << " bytes" << std::endl;
        if (rc < 0)
        {
            fprintf(stderr, "Error sending data: %s\n", ssh_get_error(my_ssh_session));
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
        // std::cout << "Sent " << enc_len << " bytes to server" << std::endl;
        total_bytes_sent += enc_len;

        // Update speed every ~1 second
        if (interval.count() >= 1000)
        {
            float speed = BYTES_TO_MBPS(total_bytes_sent, duration.count());
            std::cout << "Transfer speed: " << std::fixed << std::setprecision(2)
                      << speed << " MB/s" << std::endl;
            last_update = current_time;
        }
        // std::cout << "Total bytes sent so far: " << total_bytes_sent << std::endl;

        /* now randomize iv */

        // std::cout << "IV randomized" << std::endl;
    }
    std::cout << "File sent to server" << std::endl;

    // Close the channel and session
    cleanup_client(fp, channel, my_ssh_session);
    if (verbose)
        std::cout << "Channel and session closed" << std::endl;

    std::cout << "File " << local_file << " sent successfully!" << std::endl;

    std::cout << "Total bytes sent: " << total_bytes_sent << std::endl;

    // At the end of the transfer, add overall statistics:
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    float average_speed = BYTES_TO_MBPS(total_bytes_sent, total_duration.count());

    std::cout << "Client: Library used: " << lib_name << std::endl;
    std::cout << "\nTransfer Summary:" << std::endl;
    std::cout << "Total bytes sent: " << total_bytes_sent
              << " (" << BYTES_TO_MB(total_bytes_sent) << " MB)" << std::endl;
    std::cout << "Total time: " << std::fixed << std::setprecision(2)
              << total_duration.count() / 1000.0 << " seconds" << std::endl;
    std::cout << "Average speed: " << average_speed << " MB/s" << std::endl;

    /* calculate sha256 hash of the sent file */
    std::cout << "Calculating SHA-256 hash of sent file..." << std::endl;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        std::cerr << "Error creating hash context" << std::endl;
        return -1;
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    {
        std::cerr << "Error initializing hash context" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Reopen the file for hash calculation
    FILE *hash_fp = fopen(local_file, "rb");
    if (!hash_fp)
    {
        std::cerr << "Error reopening file for hash calculation" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    // Read file in chunks and update hash
    unsigned char hash_buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(hash_buffer, 1, sizeof(hash_buffer), hash_fp)) > 0)
    {
        if (EVP_DigestUpdate(mdctx, hash_buffer, bytes_read) != 1)
        {
            std::cerr << "Error updating hash context" << std::endl;
            fclose(hash_fp);
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }

    // Close the file
    fclose(hash_fp);

    // Finalize hash calculation
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1)
    {
        std::cerr << "Error finalizing hash context" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    // Display the hash in hex format
    std::cout << "SHA-256 hash of sent file: ";
    for (unsigned int i = 0; i < hash_len; i++)
    {
        printf("%02x", hash[i]); // Use printf with %02x for proper hex formatting
    }
    std::cout << std::endl;

    /* send this hash to server */

    return 0;
}
