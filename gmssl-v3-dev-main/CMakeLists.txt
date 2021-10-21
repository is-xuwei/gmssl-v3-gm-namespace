cmake_minimum_required(VERSION 2.8.11)
project(GmSSLPP)

set(CMAKE_MACOSX_RPATH 1)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

option(NO_RC4 "Option For Not Compile RC4" OFF)
option(NO_MD5 "Option For Not Compile RC4" OFF)
option(NO_AES "Option For Not Compile RC4" OFF)
option(NO_DES "Option For Not Compile RC4" OFF)
option(NO_CHACHA20 "Option For Not Compile RC4" OFF)
option(NO_SHA1 "Option For Not Compile RC4" OFF)
option(NO_SHA2 "Option For Not Compile RC4" OFF)

if (NO_RC4)
add_definitions(-DNO_RC4)
endif()

if (NO_MD5)
add_definitions(-DNO_MD5)
endif()

if (NO_AES)
add_definitions(-DNO_AES)
endif()

if (NO_DES)
add_definitions(-DNO_DES)
endif()

if (NO_CHACHA20)
add_definitions(-DNO_CHACHA20)
endif()

if (NO_SHA1)
add_definitions(-DNO_SHA1)
endif()

if (NO_SHA2)
add_definitions(-DNO_SHA2)
endif()

include_directories(include)

add_library(
  gmsslpp

  SHARED

  src/hex.cpp
  src/debug.cpp
  src/rand.cpp

  # default sm algors
  src/sm2_algo.cpp
  src/sm2_lib.cpp
  src/sm2_asn1.cpp
  src/sm2_prn.cpp
  src/sm3.cpp
  src/sm3_hmac.cpp
  src/sm4_common.cpp
  src/sm4_setkey.cpp
  src/sm4_enc.cpp
  src/sm4_modes.cpp
  

  # optional sm algors
  src/sm9_math.cpp
  src/zuc_core.cpp
  src/zuc_eea.cpp
  src/zuc_eia.cpp

  # optional nist algors
  src/aes.cpp
  src/aes_modes.cpp
  src/chacha20.cpp
  src/sha256.cpp
  src/sha512.cpp

  # legacy algors
  src/rc4.cpp
  src/des.cpp
  src/md5.cpp
  src/sha1.cpp

  # schemes
  src/hash_drbg.cpp
  src/hmac.cpp

  # abstract
  src/digest.cpp
  src/block_cipher.cpp

  # pkix
  src/oid.cpp
  src/asn1.cpp
  src/base64.cpp
  src/pem.cpp
  src/pbkdf2.cpp
  src/pkcs8.cpp
  src/x509_lib.cpp
  src/x509_asn1.cpp
  src/x509_ext.cpp
  src/x509_algor.cpp
  src/cms.cpp

  # for tls 1.3
  src/hkdf.cpp
  src/gf128.cpp
  src/gcm.cpp

  # ssl/tls/tlcp
  src/tls.cpp
  src/tls_trace.cpp
  src/tls12.cpp
  src/tlcp.cpp
  src/tls13.cpp

)
SET_TARGET_PROPERTIES(gmsslpp PROPERTIES VERSION 3.0 SOVERSION 3)
