/** 
 * @file protocol.h
 * @brief Protocol class declaration.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "../common/encrypt.h"

#define ID_SERVER 0
#define M1 1
#define M2 2
#define M3 3
#define SERVER 0
#define CLIENT 1


/**
 * @class Protocol protocol.h "../protocol/protocol.h"
 * @brief Manage Key exchange protocol and data exchange.
 */
class Protocol
{
        /**
         * Contanins Client ID.
         */
        uint32_t client_id;
        /**
         * Contanins Server ID.
         */
        uint32_t server_id;
        /**
         * Contanins Client Nonce.
         */
        uint32_t client_nonce;

        /**
         * Message Digest's length.
         */
        int md_len;

        /**
         * Contains Pre-shared Key.
         */
        char shared_key[EVP_MAX_KEY_LENGTH];
        /**
         * Contanins Session Key generated by server.
         */
        char session_key[EVP_MAX_KEY_LENGTH];
        /**
         * Contanins IV for current encryption.
         */
        char iv[EVP_MAX_IV_LENGTH];

        /**
         * Contanins path to logfile.
         */
        string log;

        /**
         * Encryption context.
         */
        EVP_CIPHER_CTX *enc_ctx;
        /**
         * Decryption context.
         */
        EVP_CIPHER_CTX *dec_ctx;
        /**
         * Message Digest context.
         */
        EVP_MD_CTX *md_ctx;

public:
        /**
         * Protocol Constructor.
         * @param[in]   type CLIENT or SERVER.
         * @param[in]   logfile Path to logfile.
         * @return      No value is returned.
         */
        Protocol (int type, string logfile);
        /**
         * Protocol Destructor.
         * @return      No value is returned.
         */
        ~Protocol ();
        /**
         * Sends a Key exchange message.
         * @param[in]   sd A valid socket descriptor.
         * @param[in]   type Can be M1, M2 or M3.
         * @return      0 on success, -1 on failure.
         */
        int send_message (int sd, int type);
        /**
         * Receives a Key exchange message.
         * @param[in]   sd A valid socket descriptor.
         * @param[in]   type Can be M1, M2 or M3.
         * @return      0 on success, -1 on failure.
         */
       	int receive_message (int sd, int type);
        /**
         * Sends a Data message.
         * @param[in]   sd A valid socket descriptor.
         * @param[in]   buf Contains data to be sent.
         * @param[in]   len Data length.
         * @return      0 on success, -1 on failure.
         */
        int send_data (int sd, char *buf, int len);
        /**
         * Sends a Data message.
         * @param[in]   sd A valid socket descriptor.
         * @param[out]  buf Will contain data received.
         * @param[out]  len Will contain data length.
         * @return      0 on success, -1 on failure.
         */
        int receive_data (int sd, char *&buf, int *len);
};

#endif
