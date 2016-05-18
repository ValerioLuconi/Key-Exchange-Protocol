/** 
 * @file encrypt.h
 * @brief Encrypt functions declaration.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "utility.h"

#define ENC 0
#define DEC 1

/**
 * Generates and initializes a cipher context.
 * @param[in]   k The symmetric key for encrypting.
 * @param[in]   iv The initialization vector
 * @param[in]   type The context type (encryption/decryption).
 * @return      A pointer to a valid cipher context.
 */
EVP_CIPHER_CTX *create_context (char *k, char* iv, int type);

/**
 * Generates and initializes a message digest context.
 * @return      A pointer to a valid MD context.
 */
EVP_MD_CTX *create_md_context ();

/**
 * Sets initialization vector for given cipher context (in cbc mode).
 * @param[in]   ctx A valid cipher context.
 * @param[in]   iv A random generated initialization vector.
 * @param[in]   type The context type (encryption/decryption).
 * @return      No value is returned.
 */
void set_iv (EVP_CIPHER_CTX *ctx, char *iv, int type);

/**
 * Encrypts the given text with previously specified cipher.
 * @param[in]   ctx A valid cipher context.
 * @param[in]   input Text to encrypt.
 * @param[in]   il Input length (in bytes).
 * @param[out]  ol Output encrypted text length (in bytes).
 * @return      A string containing the encrypted text.
 */
char *encrypt (EVP_CIPHER_CTX *ctx, char *input, int il, int *ol);

/**
 * Decrypts the given text with previously specified cipher.
 * @param[in]   ctx A valid cipher context.
 * @param[in]   input Text to decrypt.
 * @param[in]   il Input length (in bytes).
 * @param[out]  ol Output decrypted text length (in bytes).
 * @return      A string containing the decrypted text.
 */
char *decrypt (EVP_CIPHER_CTX *ctx, char *input, int il, int *ol);

/**
 * Computes hash from given text with previously specified algorithm.
 * @param[in]   ctx A valid MD context.
 * @param[in]   input Input to hash function.
 * @param[in]   il Input length (in bytes).
 * @return      A string containing the message digest.
 */
char *digest (EVP_MD_CTX *ctx, char *input, int il);

#endif
