/** 
 * @file encrypt.cpp
 * @brief Encrypt functions definition.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include "encrypt.h"

EVP_CIPHER_CTX *create_context (char *k, char *iv, int type)
{
        EVP_CIPHER_CTX *ctx = new EVP_CIPHER_CTX;
        EVP_CIPHER_CTX_init(ctx);
        if (type == ENC) {
                EVP_EncryptInit(ctx, EVP_aes_256_cbc(), (unsigned char *) k,
                                (unsigned char *) iv);
        }
        if (type == DEC) {
                EVP_DecryptInit(ctx, EVP_aes_256_cbc(), (unsigned char *) k,
                                (unsigned char *) iv);
        }
        return ctx;
}

EVP_MD_CTX *create_md_context ()
{
        EVP_MD_CTX *ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx, EVP_ripemd160());
        return ctx;
}

void set_iv (EVP_CIPHER_CTX *ctx, char *iv, int type)
{
        if (type == ENC)
                EVP_EncryptInit(ctx, NULL, NULL, (unsigned char *) iv);
        if (type == DEC)
                EVP_EncryptInit(ctx, NULL, NULL, (unsigned char *) iv);
}

char *encrypt (EVP_CIPHER_CTX *ctx, char *input, int il, int *ol)
{
        int p = 0;
        int n = 0;
        int len;

        len = EVP_CIPHER_CTX_block_size(ctx) + il + 1;
        char *output = new char[len];
        bzero(output, len);

        EVP_EncryptUpdate(ctx, (unsigned char *) &output[p], &n,
                          (unsigned char *) input, il);
        p += n;
        EVP_EncryptFinal(ctx, (unsigned char *) &output[p], &n);
        *ol = p + n;

        return output;
}

char *decrypt (EVP_CIPHER_CTX *ctx, char *input, int il, int *ol)
{
        int p = 0;
        int n = 0;
        int len;

        len = EVP_CIPHER_CTX_block_size(ctx) + il;
        char *output = new char[len];
        bzero(output, len);

        EVP_DecryptUpdate(ctx, (unsigned char *) &output[p], &n,
                          (unsigned char *) input, il);
        p += n;
        *ol = n;
        EVP_DecryptFinal(ctx, (unsigned char *) &output[p], &n);
        *ol += n;

        return output;
}

char *digest (EVP_MD_CTX *ctx, char *input, int il)
{
        char *output = new char[EVP_MAX_MD_SIZE];
        EVP_DigestUpdate(ctx, input, il);
        EVP_DigestFinal(ctx, (unsigned char *) output, NULL);
        EVP_DigestInit(ctx, EVP_ripemd160());
        return output;
}
