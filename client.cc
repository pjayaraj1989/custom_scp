#include "custom_scp.hh"

int main(int argc, char *argv[])
{
    ssh_session my_ssh_session = NULL;
    ssh_channel channel = NULL;
    FILE *fp = NULL;
    int rc;
    char buffer[1024];
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

    std::cout << "SSH options set: " << std::endl;
    std::cout << "Host: " << host << std::endl;
    std::cout << "User: " << user << std::endl;
    std::cout << "Port: " << port << std::endl;

    // Connect to the server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to server: %s\n", ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        return -1;
    }
    std::cout << "Connected to server" << std::endl;

    // For the client side, add this function to use "none" authentication

    // After connecting to the server
    std::cout << "Connected to server, attempting 'none' authentication" << std::endl;

    // Try "none" authentication
    rc = ssh_userauth_none(my_ssh_session, NULL);
    if (rc != SSH_AUTH_SUCCESS)
    {
        std::cerr << "Error in none authentication: " << ssh_get_error(my_ssh_session) << std::endl;
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }

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
    std::cout << "Channel created" << std::endl;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    std::cout << "Channel session opened" << std::endl;

    // Open the file to be sent
    fp = fopen(local_file, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening file\n");
        cleanup_client(fp, channel, my_ssh_session);
        return -1;
    }
    std::cout << "File opened" << std::endl;

    // Read the file and send its contents to the server
    std::cout << "Sending file " << local_file << " to server" << std::endl;
    while ((nbytes = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        // Prepare for encryption
        std::vector<uint8_t> encrypted_data;
        uint8_t tag[16]; // Authentication tag

        // Encrypt the data chunk
        /* FIXME: this should be parameterized based on the encryption lib (openssl / alcp)*/
        int encrypted_len = encrypt_aes_gcm_openssl(
            (uint8_t *)buffer, nbytes,
            aad, 12, // AAD
            key, iv,
            encrypted_data, tag);

        /* FIXME: IV, ADL should be randomized each time*/

        if (encrypted_len < 0)
        {
            std::cerr << "Encryption failed" << std::endl;
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
        uint32_t enc_len = encrypted_len;

        /* first send the tag to server */
        rc = ssh_channel_write(channel, tag, 16);
        if (rc < 0)
        {
            fprintf(stderr, "Error sending tag: %s\n", ssh_get_error(my_ssh_session));
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }

        /* now send the enc flie data in chunkss*/
        rc = ssh_channel_write(channel, encrypted_data.data(), enc_len);
        std::cout << "Sending " << enc_len << " bytes" << std::endl;
        if (rc < 0)
        {
            fprintf(stderr, "Error sending data: %s\n", ssh_get_error(my_ssh_session));
            cleanup_client(fp, channel, my_ssh_session);
            return -1;
        }
        std::cout << "Sent " << enc_len << " bytes to server" << std::endl;
    }
    std::cout << "File sent to server" << std::endl;

    // Close the channel and session
    cleanup_client(fp, channel, my_ssh_session);
    std::cout << "Channel and session closed" << std::endl;

    std::cout << "File " << local_file << " sent successfully!" << std::endl;

    return 0;
}
