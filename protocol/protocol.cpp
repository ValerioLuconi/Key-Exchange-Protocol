/** 
 * @file protocol.cpp
 * @brief Protocol class methods definition.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include "protocol.h"

Protocol::Protocol (int type, string logfile)
{
	log = logfile;
        LOG(log, "** Protocol Constructor **\n");
        
        if (type == CLIENT) {
                int fd = open("key_client", O_RDONLY);
                read(fd, (void *) &client_id, sizeof(uint32_t));
                read(fd, (void *) shared_key, EVP_MAX_KEY_LENGTH);
                close(fd);
                generate_nonce((char *) &client_nonce);

                // log
                LOG(log, "\t\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\t\tShared key: " +
                    stringbyte(shared_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "\t\tClient nonce: " + utos(client_nonce) + "\n");
        }
        server_id = ID_SERVER;
        md_ctx = create_md_context();
        md_len = EVP_MD_size(md_ctx->digest);

        // log
        LOG(log, "\t\tServer ID: " + utos(server_id) + "\n");
        LOG(log, "** End constructor **\n\n");
}

Protocol::~Protocol ()
{
        // garbage collection
        EVP_CIPHER_CTX_cleanup(enc_ctx);
        EVP_CIPHER_CTX_cleanup(dec_ctx);
        EVP_MD_CTX_destroy(md_ctx);
}

int Protocol::send_message (int sd, int type)
{
        uint32_t length;
        int len;
        int ret;
        int p = 0;

        if (type == M1) {
                // log
                LOG(log, "** Sending Message M1 **\n");

                // Send to server:
                // M1 = C_ID, S_ID, Na
                len = sizeof(uint32_t);
                length = 3 * len;
                int b_len = 4 * len;

                // message buffer
                char *buffer = new char[b_len];

                // length
                bcopy ((void *) &length, (void *) &buffer[p], len);
                p += len;

                // client_id
                bcopy ((void *) &client_id, (void *) &buffer[p], len);
                p += len;

                // server id
                bcopy ((void *) &server_id, (void *) &buffer[p], len);
                p += len;

                // client nonce
                bcopy ((void *) &client_nonce, (void *) &buffer[p], len);

                // send
                p = 0;
                do {
                        ret = write (sd, (void *) &buffer[p], b_len - p);
                        if (ret == -1)
                                return ret;
                        p += ret;
                } while (p != b_len);

                // log
                LOG(log, "\tLength: " + utos(length) + "\n");
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tClient Nonce: " + utos(client_nonce) + "\n");
                LOG(log, "** Message M1 sent **\n\n");

                // garbage collection
                delete[] buffer;
        }

        if (type == M2) {
                // log
                LOG(log, "** Sending Messagge M2 **\n");

                // buffers
                int td_len = 3 * sizeof(uint32_t) + EVP_MAX_KEY_LENGTH +
                             EVP_MAX_IV_LENGTH;
                int p_len = td_len + md_len - EVP_MAX_IV_LENGTH;
                int c_len;
                int b_len;
                char *todigest = new char[td_len];
                char *md;
                char *plaintxt = new char[p_len];
                char *ciphertxt;
                char *buffer;

                // to digest: S_ID, C_ID, Na, K, IV
                len = sizeof(uint32_t);
                bcopy ((void *) &server_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &client_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &client_nonce, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) session_key, (void *) &todigest[p],
                       EVP_MAX_KEY_LENGTH);
                p += EVP_MAX_KEY_LENGTH;
                select_random_iv(iv, EVP_MAX_IV_LENGTH);
                bcopy ((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

                // hash
                md = digest(md_ctx, todigest, td_len);

                // plaintext: S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)
                p = 0;
                bcopy ((void *) todigest, (void *) &plaintxt[p], td_len -
                       EVP_MAX_IV_LENGTH);
                p += td_len - EVP_MAX_IV_LENGTH;
                bcopy ((void *) md, (void *) &plaintxt[p], md_len);

                // ciphertext: {S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)}
                enc_ctx = create_context(shared_key, iv, ENC);
                ciphertxt = encrypt(enc_ctx, plaintxt, p_len, &c_len);

                // M2 length
                length = c_len + EVP_MAX_IV_LENGTH;

                // Send to client:
                // M2 = IV, {S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)}
                p = 0;
                b_len = length + sizeof(length);
                buffer = new char[b_len];
                bcopy ((void *) &length, (void *) &buffer[p], sizeof(length));
                p += sizeof(length);
                bcopy ((void *) iv, (void *) &buffer[p], EVP_MAX_IV_LENGTH);
                p += EVP_MAX_IV_LENGTH;
                bcopy ((void *) ciphertxt, (void *) &buffer[p], c_len);

                // send
                p = 0;
                do {
                        ret = write (sd, (void *) &buffer[p], b_len - p);
                        if (ret == -1)
                                return ret;
                        p += ret;
                } while (p != b_len);

                // log
                LOG(log, "\tLength: " + utos(length) + "\n");
                LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tClient Nonce: " + utos(client_nonce) + "\n");
                LOG(log, "\tSession Key: " + 
                    stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
                LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) +
                    "\n");
                LOG(log, "\tShared Key (encrypt): " + 
                    stringbyte(shared_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "** Message M2 sent **\n\n");

                // garbage collection
                delete[] todigest;
                delete[] md;
                delete[] plaintxt;
                delete[] ciphertxt;
                delete[] buffer;
        }

        if (type == M3) {
                // log
                LOG(log, "** Sending Message M3 **\n");

                // buffers
                int td_len = 2 * sizeof(uint32_t) + EVP_MAX_IV_LENGTH;
                int p_len = td_len + md_len - EVP_MAX_IV_LENGTH;
                int c_len;
                int b_len;
                char *todigest = new char[td_len];
                char *md;
                char *plaintxt = new char[p_len];
                char *ciphertxt;
                char *buffer;

                // to digest: C_ID, S_ID, IV
                len = sizeof(uint32_t);
                bcopy ((void *) &client_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &server_id, (void *) &todigest[p], len);
                p += len;
                select_random_iv(iv, EVP_MAX_IV_LENGTH);
                bcopy ((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

                // hash
                md = digest(md_ctx, todigest, td_len);

                // plaintext: C_ID, S_ID, h(C_ID, S_ID, IV)
                p = 0;
                bcopy ((void *) todigest, (void *) &plaintxt[p], td_len -
                       EVP_MAX_IV_LENGTH);
                p += td_len - EVP_MAX_IV_LENGTH;
                bcopy ((void *) md, (void *) &plaintxt[p], md_len);

                // ciphertext: {C_ID, S_ID, h(C_ID, S_ID, IV)}
                enc_ctx = create_context(session_key, iv, ENC);
                ciphertxt = encrypt(enc_ctx, plaintxt, p_len, &c_len);

                // M3 length
                length = c_len + EVP_MAX_IV_LENGTH;

                // Send to server:
                // M3 = IV, {C_ID, S_ID, h(C_ID, S_ID, IV)}
                p = 0;
                b_len = length + sizeof(length);
                buffer = new char[b_len];
                bcopy ((void *) &length, (void *) &buffer[p], sizeof(length));
                p += sizeof(length);
                bcopy ((void *) iv, (void *) &buffer[p], EVP_MAX_IV_LENGTH);
                p += EVP_MAX_IV_LENGTH;
                bcopy ((void *) ciphertxt, (void *) &buffer[p], c_len);

                // send
                p = 0;
                do {
                        ret = write (sd, (void *) &buffer[p], b_len - p);
                        if (ret == -1)
                                return ret;
                        p += ret;
                } while (p != b_len);

                // log
                LOG(log, "\tLength: " + utos(length) + "\n");
                LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
                LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) +
                    "\n");
                LOG(log, "\tSession Key (encrypt): " + 
                    stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "** Message M3 sent **\n\n");

                // garbage collection
                delete[] todigest;
                delete[] md;
                delete[] plaintxt;
                delete[] ciphertxt;
                delete[] buffer;
        }
        return 0;
}

int Protocol::receive_message (int sd, int type)
{
        uint32_t length;
        uint32_t tmp;
        int len;
        int ret;
        int p = 0;
        int r;

        if (type == M1) {
                // log
                LOG(log, "** Receiving Message M1 **\n");

                // Receive from client:
                // M1 = C_ID, S_ID, Na

                // receive length
                len = sizeof(length);
                r = 0;
                do {
                        ret = read(sd, (void *) (&length + r), len - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != len);
                if (length != 3 * len)
                        return -1;

                // buffer
                char *buffer = new char[length];
                r = 0;
                do {
                        ret = read(sd, (void *) &buffer[r], length - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != length);

                // client id
                bcopy((void *) &buffer[p], (void *) &client_id, len);
                if (client_id < 0)
                        return -1;
                p += len;

                // server id
                bcopy((void *) &buffer[p], (void *) &tmp, len);
                if (tmp != server_id)
                        return -1;
                p += len;

                // client nonce
                bcopy((void *) &buffer[p], (void *) &client_nonce, len);

                // get pre-shared key with client
                get_key(shared_key, "key_server", client_id);

                // log
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tClient Nonce: " + utos(client_nonce) + "\n");
                LOG(log, "\tShared Key: " +
                    stringbyte(shared_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "** Message M1 Received **\n\n");

                // garbage collection
                delete[] buffer;
        }

        if (type == M2) {
                // log
                LOG(log, "** Receiving Message M2 **\n");

                // Receive from Server:
                // M2 = IV, {S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)}

                // receive length
                len = sizeof(length);
                r = 0;
                do {
                        ret = read(sd, (void *) (&length + r), len - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != len);
                if (length < (EVP_MAX_IV_LENGTH + EVP_MAX_KEY_LENGTH + 3 * len
                    + md_len))
                        return -1;

                // buffers
                int td_len = 3 * sizeof(uint32_t) + EVP_MAX_KEY_LENGTH +
                              EVP_MAX_IV_LENGTH;
                int p_len;
                int c_len = length - EVP_MAX_IV_LENGTH;
                char *todigest = new char[td_len];
                char *md;
                char *r_md = new char[md_len];
                char *plaintxt;
                char *ciphertxt = new char[c_len];
                char *buffer = new char[length];

                // receive message
                r = 0;
                do {
                        ret = read(sd, (void *) &buffer[r], length - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != length);

                // iv
                bcopy((void *) &buffer[p], (void *) iv, EVP_MAX_IV_LENGTH);
                p += EVP_MAX_IV_LENGTH;

                // ciphertext: {S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)}
                bcopy((void *) &buffer[p], (void *) ciphertxt, c_len);

                // plaintext: S_ID, C_ID, Na, K, h(S_ID, C_ID, Na, K, IV)
                dec_ctx = create_context(shared_key, iv, DEC);
                plaintxt = decrypt(dec_ctx, ciphertxt, c_len, &p_len);

                // store & check
                p = 0;
                bcopy((void *) &plaintxt[p], (void *) &tmp, len);
                if (tmp != server_id)
                        return -1;
                p += len;
                bcopy((void *) &plaintxt[p], (void *) &tmp, len);
                if (tmp != client_id)
                        return -1;
                p += len;
                bcopy((void *) &plaintxt[p], (void *) &tmp, len);
                if (tmp != client_nonce)
                        return -1;
                p += len;
                bcopy((void *) &plaintxt[p], (void *) session_key,
                      EVP_MAX_KEY_LENGTH);
                p += EVP_MAX_KEY_LENGTH;

                // received hash
                bcopy((void *) &plaintxt[p], (void *) r_md, md_len);

                // to digest: S_ID, C_ID, Na, K, IV
                p = 0;
                len = sizeof(uint32_t);
                bcopy ((void *) &server_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &client_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &client_nonce, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) session_key, (void *) &todigest[p],
                       EVP_MAX_KEY_LENGTH);
                p += EVP_MAX_KEY_LENGTH;
                bcopy ((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

                // hash
                md = digest(md_ctx, todigest, td_len);

                // check digest
                for (int i = 0; i < md_len; i++) {
                        if (md[i] != r_md[i])
                                return -1;
                }

                // log
                LOG(log, "\tLength: " + utos(length) + "\n");
                LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tClient Nonce: " + utos(client_nonce) + "\n");
                LOG(log, "\tSession Key: " + 
                    stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
                LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) +
                    "\n");
                LOG(log, "\tShared Key (decrypt): " + 
                    stringbyte(shared_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "** Message M2 Received **\n\n");

                // garbage collection
                delete[] buffer;
                delete[] ciphertxt;
                delete[] plaintxt;
                delete[] r_md;
                delete[] todigest;
                delete[] md;
        }

        if (type == M3) {
                // log
                LOG(log, "** Receiving Message M3 **\n");

                // Receive from client:
                // M3 = IV, {C_ID, S_ID, h(C_ID, S_ID, IV)}

                // receive length
                len = sizeof(length);
                r = 0;
                do {
                        ret = read(sd, (void *) (&length + r), len - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != len);
                if (length < (EVP_MAX_IV_LENGTH + 2 * len + md_len))
                        return -1;

                // buffers
                int td_len = 2 * sizeof(uint32_t) + EVP_MAX_IV_LENGTH;
                int p_len;
                int c_len = length - EVP_MAX_IV_LENGTH;
                char *todigest = new char[td_len];
                char *md;
                char *r_md = new char[md_len];
                char *plaintxt;
                char *ciphertxt = new char[c_len];
                char *buffer = new char[length];

                // read message
                r = 0;
                do {
                        ret = read(sd, (void *) &buffer[r], length - r);
                        if (ret == -1)
                                return ret;
                        r += ret;
                } while (r != length);

                // iv
                bcopy((void *) &buffer[p], (void *) iv, EVP_MAX_IV_LENGTH);
                p += EVP_MAX_IV_LENGTH;

                // ciphertext: {C_ID, S_ID, h(C_ID, S_ID, IV)}
                bcopy((void *) &buffer[p], (void *) ciphertxt, c_len);

                // plaintext: C_ID, S_ID, h(C_ID, S_ID, IV)
                dec_ctx = create_context(session_key, iv, DEC);
                plaintxt = decrypt(dec_ctx, ciphertxt, c_len, &p_len);

                // check
                p = 0;
                len = sizeof(uint32_t);
                bcopy((void *) &plaintxt[p], (void *) &tmp, len);
                if (tmp != client_id)
                        return -1;
                p += len;
                bcopy((void *) &plaintxt[p], (void *) &tmp, len);
                if (tmp != server_id)
                        return -1;
                p += len;

                // received hash
                bcopy((void *) &plaintxt[p], (void *) r_md, md_len);

                // to digest: C_ID, S_ID, IV
                p = 0;
                bcopy ((void *) &client_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) &server_id, (void *) &todigest[p], len);
                p += len;
                bcopy ((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

                // hash
                md = digest(md_ctx, todigest, td_len);

                // check digest
                for (int i = 0; i < md_len; i++) {
                        if (md[i] != r_md[i])
                                return -1;
                }

                // log
                LOG(log, "\tLength: " + utos(length) + "\n");
                LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
                LOG(log, "\tClient ID: " + utos(client_id) + "\n");
                LOG(log, "\tServer ID: " + utos(server_id) + "\n");
                LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
                LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) +
                    "\n");
                LOG(log, "\tSession Key (decrypt): " + 
                    stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
                LOG(log, "** Message M3 sent **\n\n");

                // garbage collection
                delete[] buffer;
                delete[] ciphertxt;
                delete[] plaintxt;
                delete[] r_md;
                delete[] todigest;
                delete[] md;
        }

        return 0;
}

int Protocol::send_data (int sd, char *buf, int len)
{
        // log
        LOG(log, "** Sending Data **\n");

        int n = sizeof(uint32_t);
        int p = 0;
        uint32_t length;

        // buffers
        int td_len = 2 * n + len + EVP_MAX_IV_LENGTH;
        int p_len = td_len + md_len - EVP_MAX_IV_LENGTH;
        int c_len;
        int b_len;
        char *todigest = new char[td_len];
        char *md;
        char *plaintxt = new char[p_len];
        char *ciphertxt;
        char *buffer;

        // to digest: C_ID, S_ID, buf, IV
        bcopy((void *) &client_id, (void *) &todigest[p], n);
        p += n;
        bcopy((void *) &server_id, (void *) &todigest[p], n);
        p += n;
        bcopy((void *) buf, (void *) &todigest[p], len);
        p += len;
        select_random_iv(iv, EVP_MAX_IV_LENGTH);
        bcopy((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

        // hash
        md = digest(md_ctx, todigest, td_len);

        // plaintext: C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)
        p = 0;
        bcopy((void *) todigest, (void *) &plaintxt[p], p_len - md_len);
        p += p_len - md_len;
        bcopy((void *) md, (void *) &plaintxt[p], md_len);

        // ciphertext: {C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)}
        enc_ctx = create_context(session_key, iv, ENC);
        ciphertxt = encrypt(enc_ctx, plaintxt, p_len, &c_len);
        EVP_CIPHER_CTX_cleanup(enc_ctx);

        // Message length
        length = c_len + EVP_MAX_IV_LENGTH;

        // Send:
        // M = IV, {C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)}
        p = 0;
        b_len = length + n;
        buffer = new char[b_len];
        bcopy((void *) &length, (void *) &buffer[p], n);
        p += n;
        bcopy((void *) iv, (void *) &buffer[p], EVP_MAX_IV_LENGTH);
        p += EVP_MAX_IV_LENGTH;
        bcopy((void *) ciphertxt, (void *) &buffer[p], c_len);

        // send
        p = 0;
        int ret;
        do {
                ret = write (sd, (void *) &buffer[p], b_len - p);
                if (ret == -1)
                        return ret;
                p += ret;
        } while (p != b_len);

        // log
        LOG(log, "\tLength: " + utos(length) + "\n");
        LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
        LOG(log, "\tClient ID: " + utos(client_id) + "\n");
        LOG(log, "\tServer ID: " + utos(server_id) + "\n");
        LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
        LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) + "\n");
        LOG(log, "\tData: " + stringbyte(buf, len) + "\n");
        LOG(log, "\tSession Key (encrypt): " + 
            stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
        LOG(log, "** Data Sent **\n\n");

        // garbage collection
        delete[] todigest;
        delete[] md;
        delete[] plaintxt;
        delete[] ciphertxt;
        delete[] buffer;

        return 0;
}

int Protocol::receive_data (int sd, char *&buf, int *len)
{
        // log
        LOG(log, "** Receiving Data **\n");

        int n = sizeof(uint32_t);
        int p = 0;
        uint32_t length;

        // Receive:
        // M = IV, {C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)}

        // receive length
        int ret, r = 0;
        do {
                ret = read(sd, (void *) (&length + r), n - r);
                if (ret == -1)
                        return ret;
                r += ret;
        } while (r != n);
        if (length <= (EVP_MAX_IV_LENGTH + 2 * n + md_len))
                return -1;

        // buffers
        int td_len;
        int p_len;
        int c_len = length - EVP_MAX_IV_LENGTH;
        char *todigest;
        char *md;
        char *r_md = new char[md_len];
        char *plaintxt;
        char *ciphertxt = new char[c_len];
        char *buffer = new char[length];

        // read message
        r = 0;
        do {
                ret = read(sd, (void *) &buffer[r], length - r);
                if (ret == -1)
                        return ret;
                r += ret;
        } while (r != length);

        // iv
        bcopy((void *) &buffer[p], (void *) iv, EVP_MAX_IV_LENGTH);
        p += EVP_MAX_IV_LENGTH;

        // ciphertext:  {C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)}
        bcopy((void *) &buffer[p], (void *) ciphertxt, c_len);

        // plaintext: C_ID, S_ID, buf, h(C_ID, S_ID, buf, IV)
        dec_ctx = create_context(session_key, iv, DEC);
        plaintxt = decrypt(dec_ctx, ciphertxt, c_len, &p_len);
        EVP_CIPHER_CTX_cleanup(dec_ctx);

        // check
        uint32_t tmp;
        p = 0;
        bcopy((void *) &plaintxt[p], (void *) &tmp, n);
        if (tmp != client_id) {
                printf("esco qui\n");
                return -1;
        }
        p += n;
        bcopy((void *) &plaintxt[p], (void *) &tmp, n);
        if (tmp != server_id)
                return -1;
        p += n;

        // data
        *len = p_len - (2 * n + md_len);
        buf = new char[*len];
        bcopy((void *) &plaintxt[p], (void *) buf, *len);
        p += *len;

        // received hash
        bcopy((void *) &plaintxt[p], (void *) r_md, md_len);

        // todigest: C_ID, S_ID, buf, IV
        p = 0;
        td_len = 2 * n + *len + EVP_MAX_IV_LENGTH;
        todigest = new char[td_len];
        bcopy((void *) &client_id, (void *) &todigest[p], n);
        p += n;
        bcopy((void *) &server_id, (void *) &todigest[p], n);
        p += n;
        bcopy((void *) buf, (void *) &todigest[p], *len);
        p += *len;
        bcopy((void *) iv, (void *) &todigest[p], EVP_MAX_IV_LENGTH);

        // hash
        md = digest(md_ctx, todigest, td_len);

        // check hash
        for (int i = 0; i < md_len; i++) {
                if (md[i] != r_md[i])
                        return -1;
        }

        // log
        LOG(log, "\tLength: " + utos(length) + "\n");
        LOG(log, "\tIV: " + stringbyte(iv, EVP_MAX_IV_LENGTH) + "\n");
        LOG(log, "\tClient ID: " + utos(client_id) + "\n");
        LOG(log, "\tServer ID: " + utos(server_id) + "\n");
        LOG(log, "\tMD: " + stringbyte(md, md_len) + "\n");
        LOG(log, "\tCipher Text: " + stringbyte(ciphertxt, c_len) + "\n");
        LOG(log, "\tData: " + stringbyte(buf, *len) + "\n");
        LOG(log, "\tSession Key (decrypt): " + 
            stringbyte(session_key, EVP_MAX_KEY_LENGTH) + "\n");
        LOG(log, "** Data Received **\n\n");

        // garbage collection
        delete[] todigest;
        delete[] md;
        delete[] r_md;
        delete[] plaintxt;
        delete[] ciphertxt;
        delete[] buffer;

        return 0;
}
