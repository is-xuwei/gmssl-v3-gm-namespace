#include "gm.h"
#include "gmssl/sm3.h"
#include "gmssl/sm4.h"
#include "stdio.h"

using namespace gm;

    const unsigned char PADDING_BYTE[] = { 0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    void do_padding(const unsigned char* in, unsigned char* out, size_t* len, int alg = PADDING_PBOC)
    {
        memcpy(out, in, *len);
        char padding_num = 16 - (*len % 16);
        memcpy(out + *len, PADDING_BYTE, padding_num);
        *len += padding_num;
    }

    void do_unpadding(unsigned char* in, size_t* len, int alg = PADDING_PBOC)
    {
        for (int i = *len - 1; i > *len - 16; i--)
        {
            if (in[i] == 0x80)
            {
                *len = i;
                return;
            }
        }
    }

    void gm_sm3(const unsigned char* data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH])
    {
        sm3_digest(data, datalen, digest);
    }

    void gm_sm3_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char mac[SM3_HMAC_SIZE])
    {
        sm3_hmac(data, data_len, key, key_len, mac);
    }

    void gm_sm4_ecb_encrypt(const unsigned char* in, unsigned char* out, const unsigned char user_key[16], int enc)
    {
        SM4_KEY key;
        if (enc)
            sm4_set_encrypt_key(&key, user_key);
        else
            sm4_set_decrypt_key(&key, user_key);
        sm4_encrypt(&key, in, out);
    }

    void gm_sm4_cbc_encrypt(const unsigned char* in, unsigned char* out, size_t len, const unsigned char user_key[16], const unsigned char* iv, int enc)
    {
        SM4_KEY key;
        unsigned char _iv[16] = { 0 };
        memcpy(_iv, iv, 16);
        if (enc)
        {
            sm4_set_encrypt_key(&key, user_key);
            sm4_cbc_encrypt(&key, _iv, in, len / 16, out);
        }
        else
        {
            sm4_set_decrypt_key(&key, user_key);
            sm4_cbc_decrypt(&key, _iv, in, len / 16, out);
        }
    }

    void gm_sm4(const unsigned char* in, unsigned char* out, size_t* len, const unsigned char user_key[16], const unsigned char* iv, int enc = 1, int type = SGD_SM4_ECB, int padding = PADDING_PBOC)
    {
        unsigned char* buff_in;
        //size_t buff_in_len = len;

        SM4_KEY key;
        if (enc)
        {
            buff_in = new unsigned char[*len + 16];
            do_padding(in, buff_in, len);
            //buff_in_len = len;
            sm4_set_encrypt_key(&key, user_key);
        }
        else
        {
            buff_in = (unsigned char*)in;
            sm4_set_decrypt_key(&key, user_key);
        }

        if (type == SGD_SM4_ECB)
        {
            size_t step = 0;
            while (step < *len)
            {
                sm4_encrypt(&key, buff_in + step, out + step);
                step += 16;
            }
        }
        else if (type == SGD_SM4_CBC)
        {
            unsigned char _iv[16] = { 0 };
            memcpy(_iv, iv, 16);
            if (enc)
            {
                sm4_cbc_encrypt(&key, _iv, buff_in, *len / 16, out);
            }
            else
            {
                sm4_cbc_decrypt(&key, _iv, buff_in, *len / 16, out);
            }
        }
        else
        {
            printf("Error: type not in [SGD_SM4_ECB, SGD_SM4_CBC]\n");
            exit(-1);
        }

        if (enc != 1)
        {
            do_unpadding(out, len);
        }
    }
