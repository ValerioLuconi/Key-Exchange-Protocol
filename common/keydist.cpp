/** 
 * @file keydist.cpp
 * @brief Offline key distribution to client.
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
 * @param[in]   argv[1] Client ID.
 */
int main (int argc, char *argv[])
{
        if (argc != 2) {
                cout<<"Keydist: Bad arguments\nSyntax: ./keydist client_id\n";
                return 1;
        }

        char k[EVP_MAX_KEY_LENGTH];
        uint32_t id = atoi(argv[1]);

        int sfd = open("../server/key_server", O_RDONLY);
        if (sfd < 0) {
                cout<<"Keydist: Unable to read file key_server\n";
                return 1;
        }

        lseek(sfd, (id - 1) * EVP_MAX_KEY_LENGTH, SEEK_SET);
        read(sfd, (void *) k, EVP_MAX_KEY_LENGTH);
        close(sfd);

        int cfd = open("../client/key_client", O_WRONLY | O_CREAT,
                       S_IRUSR | S_IWUSR);
        if (cfd < 0) {
                cout<<"Keydist: Unable to open or create file key_client\n";
                return 1;
        }

        write(cfd, (void *) &id, sizeof(id));
        write(cfd, (void *) k, EVP_MAX_KEY_LENGTH);

        close(cfd);

        // print client's file
        cfd = open("../client/key_client", O_RDONLY);
        read(cfd, (void *) &id, sizeof(id));
        cout<<"Keydist:\n\tClient "<<id<<"\n\t";
        read(cfd, (void *) k, EVP_MAX_KEY_LENGTH);
        for (int i = 0; i < EVP_MAX_KEY_LENGTH; i++)
                printbyte(k[i]);
        cout<<"\n";

        return 0;
}
