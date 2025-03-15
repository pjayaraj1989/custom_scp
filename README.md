# custom_scp
An experiment to demonstrate custom SCP client server communication

# prerequisite
1. generate server keys by running the script gen_certs.sh
2. Compile custom libssh by disabling encryption
3. https://github.com/libssh
4. Apply the attached patch and compile.
5. cmake -B ./build -DWITH_INSECURE_NONE=ON -DWITH_GCRYPT=OFF -DWITH_MBEDTLS=OFF -DCMAKE_INSTALL_PREFIX=$HOME/openssh_no_encryption -DWITH_BLOWFISH_CIPHER=OFF  -DDEBUG_CALLTRACE=ON -DHAVE_LIBCRYPTO=OFF -DCMAKE_BUILD_TYPE=Debug -DHAVE_OPENSSL_EVP_CHACHA20=OFF;
6. cmake --build -B ./build; cmake --install -B ./build;
7. Now pass this custom compiled libssh path to client and server application compilation:
8. cmake ../ -DOPENSSH_INSTALL_DIR=$HOME/openssh_no_encryption -DCMAKE_BUILD_TYPE=Debug; make -j;
9. Run server, and client application.
10. By default this solution uses OpenSSL's EVP_Encrypt* APIs, replace them with custom crypto libraries to use them in your applciation.
