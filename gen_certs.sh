#openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes

ssh-keygen -t rsa -b 2048 -f server_rsa_key -N ""
