CMAKE_MINIMUM_REQUIRED(VERSION 3.4.1)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picotcpls)

FIND_PACKAGE(PkgConfig REQUIRED)
INCLUDE(cmake/dtrace-utils.cmake)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

CHECK_DTRACE(${PROJECT_SOURCE_DIR}/picotls-probes.d)
OPTION(WITH_DTRACE "use USDT (userspace Dtrace probes)" ${HAVE_DTRACE})
IF (WITH_DTRACE)
    MESSAGE(STATUS "Enabling USDT support")
ENDIF ()

SET(CMAKE_C_FLAGS "-std=c99 -O2 -g3 -Wall ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
SET(PYTHON_EXECUTABLE, "python3")
INCLUDE_DIRECTORIES(
    deps/cifra/src/ext
    deps/cifra/src
    deps/micro-ecc
    deps/picotest
    include
    ${CMAKE_CURRENT_BINARY_DIR})
SET(MINICRYPTO_LIBRARY_FILES
    deps/micro-ecc/uECC.c
    deps/cifra/src/aes.c
    deps/cifra/src/blockwise.c
    deps/cifra/src/chacha20.c
    deps/cifra/src/chash.c
    deps/cifra/src/curve25519.c
    deps/cifra/src/drbg.c
    deps/cifra/src/hmac.c
    deps/cifra/src/gcm.c
    deps/cifra/src/gf128.c
    deps/cifra/src/modes.c
    deps/cifra/src/poly1305.c
    deps/cifra/src/sha256.c
    deps/cifra/src/sha512.c)
SET(CORE_FILES
    lib/containers.c
    lib/heap.c
    lib/pembase64.c
    lib/picotls.c
    lib/picotcpls.c
    lib/rsched.c)
SET(CORE_TEST_FILES
    t/picotls.c)
IF (WITH_DTRACE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_DTRACE=1")
    DEFINE_DTRACE_DEPENDENCIES(${PROJECT_SOURCE_DIR}/picotls-probes.d picotls)
    LIST(APPEND CORE_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    LIST(APPEND CORE_TEST_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    IF (DTRACE_USES_OBJFILE)
        LIST(APPEND CORE_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
        LIST(APPEND CORE_TEST_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
    ENDIF ()
ENDIF ()

ADD_LIBRARY(picotls-core
            SHARED
            ${CORE_FILES})
TARGET_LINK_LIBRARIES(picotls-core ${CORE_EXTRA_LIBS})

ADD_LIBRARY(picotls-minicrypto
    SHARED
    ${MINICRYPTO_LIBRARY_FILES}
    lib/cifra.c
    lib/cifra/x25519.c
    lib/cifra/chacha20.c
    lib/cifra/aes128.c
    lib/cifra/aes256.c
    lib/cifra/random.c
    lib/minicrypto-pem.c
    lib/uecc.c
    lib/asn1.c
    lib/ffx.c)
TARGET_LINK_LIBRARIES(picotls-minicrypto picotls-core)

SET(OPENSSL_INCLUDE_DIR /home/aubuchet/Documents/tcpls_app/app/app/src/main/cpp/openssl/include)
SET(OPENSSL_LIBRARIES /home/aubuchet/Documents/tcpls_app/app/app/src/main/cpp/openssl/libcrypto.so /home/aubuchet/Documents/tcpls_app/app/app/src/main/cpp/openssl/libssl.so)

ADD_LIBRARY(cli
            SHARED
            t/cli.c)

ADD_LIBRARY(picotcpls-jni
            SHARED
            jni/logger.c
            jni/jniclient.c)

MESSAGE(STATUS "Enabling OpenSSL support")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
ADD_LIBRARY(picotls-openssl
            SHARED
            lib/openssl.c)
TARGET_LINK_LIBRARIES(picotls-openssl ${OPENSSL_LIBRARIES} picotls-core ${CMAKE_DL_LIBS})
TARGET_LINK_LIBRARIES(cli picotls-openssl picotls-core)
TARGET_LINK_LIBRARIES(picotcpls-jni picotls-openssl picotls-core)


IF ((CMAKE_SIZEOF_VOID_P EQUAL 8) AND
    (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64") OR
     (CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64") OR
     (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64"))
    MESSAGE(STATUS " Enabling fusion support")
    ADD_LIBRARY(picotls-fusion lib/fusion.c)
    SET_TARGET_PROPERTIES(picotls-fusion PROPERTIES COMPILE_FLAGS "-mavx2 -maes -mpclmul")
    TARGET_LINK_LIBRARIES(picotls-fusion picotls-core)
ENDIF ()




IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "-D_GNU_SOURCE -pthread ${CMAKE_C_FLAGS}")
ELSEIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    TARGET_LINK_LIBRARIES(cli "socket" "nsl")
ENDIF ()

FIND_LIBRARY(LIBC_RESOLV_LIB "resolv")
IF (OPENSSL_FOUND AND LIBC_RESOLV_LIB)
    MESSAGE("Resolve Support")
    TARGET_LINK_LIBRARIES(cli ${LIBC_RESOLV_LIB})
    TARGET_LINK_LIBRARIES(picotcpls-jni ${LIBC_RESOLV_LIB})
ENDIF ()

FIND_LIBRARY(log-lib log )

MESSAGE(${log-lib})

TARGET_LINK_LIBRARIES(picotcpls-jni -llog picotls-core picotls-openssl ${OPENASSL_LIBRARIES})

TARGET_LINK_LIBRARIES(cli picotls-core picotls-openssl ${OPENSSL_LIBRARIES})
