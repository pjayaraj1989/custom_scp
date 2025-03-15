#include "custom_scp.hh"

int main()
{
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
    std::cout << "Connection accepted" << std::endl;

    if (ssh_handle_key_exchange(session))
    {
        fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    std::cout << "Key exchange completed" << std::endl;

    // auto-accept any authentication request
#if 1
    int auth = 0;
    while (!auth)
    {
        std::cout << "Inside authentication check loop" << std::endl;
        message = ssh_message_get(session);
        if (message == NULL)
        {
            std::cout << "Message is null" << std::endl;
            break;
        }
        std::cout << "Msg received from session" << std::endl;

        int msg_type = ssh_message_type(message);
        std::cout << "Message type: " << msg_type << std::endl;

        if (msg_type == SSH_REQUEST_SERVICE)
        {
            // Accept any service request
            const char *service = ssh_message_service_service(message);
            std::cout << "Requested service: " << (service ? service : "NULL") << std::endl;
            ssh_message_service_reply_success(message);
        }
        else if (msg_type == SSH_REQUEST_AUTH)
        {
            // Auto-accept any authentication request without checking credentials
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
#endif

    std::cout << "Authenticated, waiting for client channel requests" << std::endl;

    int channel_established = 0;
    while (!channel_established)
    {
        message = ssh_message_get(session);
        if (message == NULL)
        {
            std::cout << "Message is null while waiting for channel" << std::endl;
            break;
        }
        int msg_type = ssh_message_type(message);
        std::cout << "Message type: " << msg_type << std::endl;
        if (msg_type == SSH_REQUEST_CHANNEL_OPEN)
        {
            std::cout << "Channel open request received" << std::endl;
            if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION)
            {
                std::cout << "Session channel requested, accepting" << std::endl;
                channel = ssh_message_channel_request_open_reply_accept(message);
                if (channel != NULL)
                {
                    channel_established = 1;
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
            std::cout << "Channel request received" << std::endl;
            int req_type = ssh_message_subtype(message);
            std::cout << "Channel request type: " << req_type << std::endl;

            // Handle specific channel requests like exec, shell, subsystem
            if (req_type == SSH_CHANNEL_REQUEST_EXEC)
            {
                std::cout << "Channel req type received is REQUEST_EXEC" << std::endl;
                const char *command = ssh_message_channel_request_command(message);
                std::cout << "Exec request: " << (command ? command : "NULL") << std::endl;

                // Check if it's an SCP command
                if (command && strncmp(command, "scp", 3) == 0)
                {
                    ssh_message_channel_request_reply_success(message);
                    std::cout << "Accepted SCP exec request" << std::endl;
                }
                else
                {
                    ssh_message_reply_default(message);
                }
            }
            else
            {
                std::cout << "Channel default reply" << std::endl;
                ssh_message_reply_default(message);
            }
        }
        else
        {
            std::cout << "Unexpected message type, ignoring" << std::endl;
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (!channel_established)
    {
        std::cout << "Failed to establish channel with client" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    /* just cross check if channel is open for data transfer */
    if (ssh_channel_is_open(channel))
    {
        std::cout << "Channel is open" << std::endl;
    }
    else
    {
        std::cout << "Channel is closed" << std::endl;
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }

    std::cout << "Reading data from channel" << std::endl;
    int nbytes;
    char buffer[1024];

    fp = fopen(received_file, "wb");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening output file\n");
        cleanup_server(fp, channel, session, sshbind);
        return -1;
    }
    std::cout << "File opened for writing" << std::endl;

    uint8_t tag[16];
    std::vector<uint8_t> decrypted_data;

    /* in a loop, first read the tag, then the buffer */
    while (1)
    {
        nbytes = ssh_channel_read(channel, tag, sizeof(tag), 0);
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

        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0)
        {
            std::cerr << "Failed to read data" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
        /* call decrypt */
        /* FIXME: Make this parameterized, based on lib type (alcp / openssl / etc)*/
        int dec_len = decrypt_aes_gcm_openssl((uint8_t *)buffer, nbytes, aad, 12, tag, key, iv, decrypted_data);
        if (dec_len < 0)
        {
            std::cerr << "Decryption function failed" << std::endl;
            cleanup_server(fp, channel, session, sshbind);
            return -1;
        }
        fwrite(decrypted_data.data(), 1, dec_len, fp);
        std::cout << "Successfully Decrpyted and wrote " << dec_len << " bytes" << std::endl;
    }

    std::cout << "File received and saved: " << received_file << std::endl;
    cleanup_server(fp, channel, session, sshbind);
    std::cout << "Session closed" << std::endl;

    return 0;
}
