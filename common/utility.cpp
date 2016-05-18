/** 
 * @file utility.cpp
 * @brief Utility functions definition.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include "utility.h"

int seed_prng(int bytes)
{
        if (!RAND_load_file("dev/random", bytes))
                return 0;
        return 1;
}

void select_random_key(char *k, int len)
{
        RAND_bytes((unsigned char *) k, len);
}

void select_random_iv(char *iv, int len)
{
        RAND_pseudo_bytes((unsigned char *) iv, len);
}

void generate_nonce(char *nonce)
{
        RAND_pseudo_bytes((unsigned char*) nonce, sizeof(uint32_t));
}

void printbyte (char b)
{
        char c;
        c = b;
        c = c >> 4;
        c = c & 15;
        printf("%X", c);
        c = b;
        c = c & 15;
        printf("%X", c);
}

int get_key (char *k, string path, int n)
{
        int ret;
        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1)
                return fd;
        ret = lseek(fd, (n - 1) * EVP_MAX_KEY_LENGTH, SEEK_SET);
        if (ret == -1)
                return ret;
        ret = read(fd, (void *) k, EVP_MAX_KEY_LENGTH);
        if (ret == -1)
                return ret;
        close(fd);
        return 0;
}

int LOG (string path, string s)
{
        int ret;
        int fd = open(path.c_str(), O_WRONLY | O_APPEND);
        if (fd == -1)
                return fd;
        ret = write(fd, (void *) s.c_str(), s.size());
        if (ret == -1)
                return ret;
        close(fd);
        return 0;
}

string stringbyte(char *b, int l)
{
        char tmp;
        string str;
        for (int i = 0; i < l; i++) {
                char c;
                c = b[i];
                c = c >> 4;
                c = c & 15;
                sprintf(&tmp, "%X", c);
                str.append(&tmp, 1);
                c = b[i];
                c = c & 15;
                sprintf(&tmp, "%X", c);
                str.append(&tmp, 1);
        }
        return str;
}

string utos(uint32_t n)
{
        char tmp[10];
        sprintf(tmp, "%u", n);
        string str(tmp);
        return str;
}
