/** 
 * @file utility.h
 * @brief Utility functions declaration.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#ifndef UTILITY_H
#define UTILITY_H

#include <iostream>
#include <string>
#include <stdlib.h> 
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
using namespace std;


/**
 * Seeds the pseudo-random number generator.
 * @param[in]   bytes Seed length (in bytes).
 * @return      1 on success, 0 otherwise.
 */
int seed_prng(int bytes);

/**
 * Generates a random key.
 * @param[out]  k The generated key.
 * @param[in]   len Key length.
 * @return      No value is returned.
 */
void select_random_key(char *k, int len);

/**
 * Generates a random initialization vector.
 * @param[out]  iv The generated initialization vector.
 * @param[in]   len IV length.
 * @return      No value is returned.
 */
void select_random_iv(char *iv, int len);

/**
 * Generates 32 bits random nonce.
 * @param[out]  nonce The generated nonce.
 * @return      No value is returned.
 */
void generate_nonce(char *nonce);

/**
 * Prints a given byte to screen in hexadecimal digits.
 * @param[in]   b Byte to be printed.
 * @return      No value is returned.
 */
void printbyte(char b);

/**
 * Converts a C string in a C++ string object (in hexadecimal digits).
 * @param[in]   b The given C string.
 * @param[in]   l C string length (in characters).
 * @return      A C++ string object in hexadecimal digits.
 */
string stringbyte(char *b, int l);

/**
 * Gets an EVP key (of EVP_MAX_KEY_LENGTH bytes) from a given file.
 * @param[out]  k The returned key.
 * @param[in]   path A string containing path to file.
 * @param[in]   n Key position in file.
 * @return      0 on success, -1 on failure.
 */
int get_key(char *k, string path, int n);

/**
 * Writes on a given file a given string
 * @param[in]   path A string containing path to file.
 * @param[in]   s The string to be written.
 * @return      0 on success, -1 on failure
 */
int LOG(string path, string s);

/**
 * Converts an uint32_t in a C++ string in decimal digits.
 * @param[in]   n Given number, must be uint32_t type.
 * @return      A string with decimal representation of given number.
 */
string utos(uint32_t n);

#endif
