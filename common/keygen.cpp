/** 
 * @file keygen.cpp
 * @brief Offline key generation.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <errno.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include "utility.h"
using namespace std;

/**
 * Main function
 * @param[in]   argc Number of arguments.
 * @param[in]   argv[0] Program's name.
 * @param[in]   argv[1] Number of keys generated.
 */
int main (int argc, char *argv[])
{
        if (argc != 2) {
                cout<<"Keygen: Bad arguments\nSyntax: ./keygen clients_number\n";
                return 1;
        }

        int n = atoi(argv[1]);
        char k[EVP_MAX_KEY_LENGTH];

        int fd = open("../server/key_server", O_WRONLY | O_CREAT,
                      S_IRUSR | S_IWUSR);

        for (int i = 0; i < n; i++) {
                select_random_key(k, EVP_MAX_KEY_LENGTH);
                write(fd, (void *) k, EVP_MAX_KEY_LENGTH);
        }

        close(fd);

        // print file content
        fd = open("../server/key_server", O_RDONLY);
        cout<<"Keygen:\n";
        for (int i = 1; i <= n; i++) {
                read(fd, (void *) k, EVP_MAX_KEY_LENGTH);
                cout<<"\tClient "<<i<<"\n\t";
                for (int j = 0; j < EVP_MAX_KEY_LENGTH; j++)
                        printbyte(k[j]);
                cout<<"\n";
        }
        close(fd);
        return 0;
}
