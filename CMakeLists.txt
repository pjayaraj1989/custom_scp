cmake_minimum_required(VERSION 3.10)
project(custom_scp_experiments)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add current directory so headers like inc.hh are found
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# if custom openssh install dir is specified, use that, else use default openssh
if (OPENSSH_INSTALL_DIR)
    message(STATUS "Using custom OPENSSH_INSTALL_DIR: ${OPENSSH_INSTALL_DIR}")
    find_library(SSH_LIB NAMES ssh
                 PATHS ${OPENSSH_INSTALL_DIR}/lib
                 NO_DEFAULT_PATH)
    if(NOT SSH_LIB)
        message(FATAL_ERROR "libssh not found")
    endif()
    message(STATUS "SSH_LIB: ${SSH_LIB}")
else()
    message(STATUS "OPENSSH_INSTALL_DIR not set. Using default openssh")
endif()

# common sources
set(COMMON_SOURCES
    openssl_cipher.cc
)

# Create two executables: client and server
add_executable(client client.cc ${COMMON_SOURCES})
add_executable(server server.cc ${COMMON_SOURCES})

# check if ${SSH_LIB} is set
if(SSH_LIB)
    target_link_libraries(client PUBLIC ${SSH_LIB} "-lssh" "-lcrypto")
    target_link_libraries(server PUBLIC ${SSH_LIB} "-lssh" "-lcrypto")
else()
    target_link_libraries(client PUBLIC "-lssh" "-lcrypto")
    target_link_libraries(server PUBLIC "-lssh" "-lcrypto")
endif()

file(GLOB KEY_FILES "${CMAKE_CURRENT_SOURCE_DIR}/server_rsa_key*")
file(GLOB FILES_TO_COPY "${CMAKE_CURRENT_SOURCE_DIR}/*.txt")

foreach(key ${KEY_FILES})
    message(STATUS "Symlinking ${key}")
    get_filename_component(key_file_name ${key} NAME)
    file(CREATE_LINK ${key} ${CMAKE_CURRENT_BINARY_DIR}/${key_file_name} SYMBOLIC)
endforeach()

foreach(file_to_copy ${FILES_TO_COPY})
    message(STATUS "Symlinking ${file_to_copy}")
    get_filename_component(file_to_copy_name ${file_to_copy} NAME)
    file(CREATE_LINK ${file_to_copy} ${CMAKE_CURRENT_BINARY_DIR}/${file_to_copy_name} SYMBOLIC)
endforeach()
