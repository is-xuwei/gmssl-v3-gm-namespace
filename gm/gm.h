#pragma once
#include <stdlib.h>


#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		    (SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE		(SM3_DIGEST_LENGTH)

#define sm4_KEY_LENGTH		16
#define sm4_BLOCK_SIZE		16
#define sm4_IV_LENGTH		(sm4_BLOCK_SIZE)
#define sm4_NUM_ROUNDS		32

// padding.
#define NO_PADDING 0
#define PADDING_PKCS 1
#define PADDING_PBOC 2

//对称算法标识
#define SGD_SM1           	0x00000100
#define SGD_SM1_ECB       	0x00000101
#define SGD_SM1_CBC       	0x00000102
#define SGD_SM1_CFB        	0x00000104
#define SGD_SM1_OFB        	0x00000108
#define SGD_SM1_MAC        	0x00000110
#define SGD_SM1_CTR        	0x00000120

#define SGD_SSF33        	0x00000200
#define SGD_SSF33_ECB    	0x00000201
#define SGD_SSF33_CBC    	0x00000202
#define SGD_SSF33_CFB    	0x00000204
#define SGD_SSF33_OFB    	0x00000208
#define SGD_SSF33_MAC    	0x00000210
#define SGD_SSF33_CTR    	0x00000220

#define SGD_SM4            	0x00000400
#define SGD_SM4_ECB        	0x00000401
#define SGD_SM4_CBC        	0x00000402
#define SGD_SM4_CFB        	0x00000404
#define SGD_SM4_OFB        	0x00000408
#define SGD_SM4_MAC        	0x00000410
#define SGD_SM4_CTR        	0x00000420

#define SGD_DES         	0x00001000
#define SGD_DES_ECB     	0x00001001
#define SGD_DES_CBC     	0x00001002
#define SGD_DES_CFB     	0x00001004
#define SGD_DES_OFB     	0x00001008
#define SGD_DES_MAC     	0x00001010
#define SGD_DES_CTR     	0x00001020

#define SGD_3DES        	0x00002000
#define SGD_3DES_ECB    	0x00002001
#define SGD_3DES_CBC    	0x00002002
#define SGD_3DES_CFB    	0x00002004
#define SGD_3DES_OFB    	0x00002008
#define SGD_3DES_MAC    	0x00002010
#define SGD_3DES_CTR    	0x00002020

#define SGD_AES         	0x00004000
#define SGD_AES_ECB     	0x00004001
#define SGD_AES_CBC     	0x00004002
#define SGD_AES_CFB     	0x00004004
#define SGD_AES_OFB     	0x00004008
#define SGD_AES_MAC     	0x00004010
#define SGD_AES_CTR     	0x00004010

//非对称算法标识
#ifndef SDF_DEEPFLOW
#define SGD_RSA          	0x00010000
#define SGD_RSA_SIGN     	0x00010100
#define SGD_RSA_ENC      	0x00010200
#endif

#define SGD_SM2          	0x00020100
#define SGD_SM2_1        	0x00020200
#define SGD_SM2_2        	0x00020400
#define SGD_SM2_3        	0x00020800

#define SGD_SM3           	0x00000001
#define SGD_SHA1          	0x00000002
#define SGD_SHA224        	0x00000020
#define SGD_SHA256        	0x00000004

#define SGD_SHA384        	0x00000008
#define SGD_SHA512        	0x00000010
#define SGD_MD5           	0x00000040


#ifdef __cplusplus
extern "C" {
#endif
 
    void do_padding(const unsigned char* in, unsigned char* out, size_t* len, int alg);

    void do_unpadding(unsigned char* in, size_t* len, int alg);

    void gm_sm3(const unsigned char* data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);

    void gm_sm3_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char mac[SM3_HMAC_SIZE]);

    void gm_sm4_ecb_encrypt(const unsigned char* in, unsigned char* out, const unsigned char user_key[16], int enc);

    void gm_sm4_cbc_encrypt(const unsigned char* in, unsigned char* out, size_t len, const unsigned char user_key[16], const unsigned char* iv, int enc);

    void gm_sm4(const unsigned char* in, unsigned char* out, size_t* len, const unsigned char user_key[16], const unsigned char* iv, int enc, int type, int padding);


#ifdef __cplusplus
}
#endif