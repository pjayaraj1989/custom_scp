cmake_minimum_required(VERSION 3.10)
project(custom_scp_experiments)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_AEAD "Enable AEAD encryption mode" OFF)

# Configure compiler definitions based on options
if(ENABLE_AEAD)
    add_definitions(-DENABLE_AEAD=1)
    message(STATUS "AEAD encryption mode enabled")
else()
    add_definitions(-DENABLE_AEAD=0)
    message(STATUS "Using Non AEAD encryption mode")
endif()

# Add current directory so headers like inc.hh are found
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

if (OPENSSL_INSTALL_DIR)
    message(STATUS "Using custom OPENSSL_INSTALL_DIR: ${OPENSSL_INSTALL_DIR}")
    find_library(OPENSSL_LIB NAMES crypto
                 PATHS ${OPENSSL_INSTALL_DIR}/lib64
                 NO_DEFAULT_PATH)
    if(NOT OPENSSL_LIB)
        message(FATAL_ERROR "libcrypto not found")
    endif()
    message(STATUS "OPENSSL_LIB: ${OPENSSL_LIB}")
else()
    message(FATAL_ERROR "OPENSSL_INSTALL_DIR not set")
    message(STATUS "Please set OPENSSL_INSTALL_DIR to the directory where OpenSSL is installed")
endif()

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

if (ALCP_INSTALL_DIR)
    message(STATUS "Using custom ALCP_INSTALL_DIR: ${ALCP_INSTALL_DIR}")
    find_library(ALCP_LIB NAMES alcp libalcp.so
                 PATHS ${ALCP_INSTALL_DIR}/lib
                 NO_DEFAULT_PATH)
    if(NOT ALCP_LIB)
        message(FATAL_ERROR "libalcp not found")
    endif()
    message(STATUS "found ALCP_LIB: ${ALCP_LIB}")

    if (NOT AOCL_UTILS_INSTALL_DIR)
        message(FATAL_ERROR "AOCL_UTILS_INSTALL_DIR not set")
    else()
        message(STATUS "Using custom AOCL_UTILS_INSTALL_DIR: ${AOCL_UTILS_INSTALL_DIR}")
        find_library(AU_LIB NAMES aoclutils libaoclutils.so
                 PATHS ${AOCL_UTILS_INSTALL_DIR}/lib
                 NO_DEFAULT_PATH)
    if(NOT AU_LIB)
        message(FATAL_ERROR "libaoclutils not found")
    endif()
    message(STATUS "found AU_LIB: ${AU_LIB}")
    endif()
endif()

# common sources
set(COMMON_SOURCES
    ${CMAKE_SOURCE_DIR}/openssl_cipher.cc
    ${CMAKE_SOURCE_DIR}/key_exchange.cc
)

if (ALCP_INSTALL_DIR)
    include_directories(${ALCP_INSTALL_DIR}/include)
    set(COMMON_SOURCES ${COMMON_SOURCES} ${CMAKE_SOURCE_DIR}/alcp_cipher.cc)
endif()

# Create two executables: client and server
add_executable(client client.cc ${COMMON_SOURCES})
add_executable(server server.cc ${COMMON_SOURCES})

set (LFLAGS "-lssh -lcrypto")
if (ALCP_INSTALL_DIR)
    set(LFLAGS "${LFLAGS} -L${ALCP_INSTALL_DIR}/lib -L${AOCL_UTILS_INSTALL_DIR}/lib -laoclutils -lalcp")
endif()

# check if ${SSH_LIB} is set
if(SSH_LIB)
    target_link_libraries(client PUBLIC ${SSH_LIB} ${OPENSSL_LIB} ${AU_LIB} ${ALCP_LIB} ${LFLAGS})
    target_link_libraries(server PUBLIC ${SSH_LIB} ${OPENSSL_LIB} ${AU_LIB} ${ALCP_LIB} ${LFLAGS})
else()
    target_link_libraries(client PUBLIC ${LFLAGS})
    target_link_libraries(server PUBLIC ${LFLAGS})
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
