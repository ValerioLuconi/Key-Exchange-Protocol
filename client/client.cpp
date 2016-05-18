/** 
 * @file client.cpp
 * @brief Simple Client for testing key exchange protocol.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include "../protocol/protocol.h"

/**
 * Connects to Server.
 * @param[in]   addr Server's IP address.
 * @param[in]   port Server port.
 * @return      A valid socket descriptor connected to server on success, -1 on failure.
 */
int connection (char *addr, int port)
{
        int sd = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in address;
        bzero(&address, sizeof(sockaddr_in));
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        inet_pton(AF_INET, addr, &address.sin_addr);

        int ret = connect(sd, (sockaddr *) &address, sizeof(sockaddr_in));

        if (ret == -1)
                return ret;
        else
                return sd;
}

/**
 * Main function.
 * @param[in]   argc Number of arguments.
 * @param[in]   argv[0] Program name.
 * @param[in]   argv[1] Server Address.
 * @param[in]   argv[2] Server Port.
 * @param[in]   argv[3, ..., N] Message for Server.
 */
int main(int argc, char *argv[])
{
        if (argc < 4) {
                cout<<"Client: Bad arguments\nSyntax:\n./client address port message\n";
                exit(1);
        }

        char *address = argv[1];
        int port = atoi(argv[2]);
        string data(argv[3]);
        for (int i = 4; i < argc; i++) {
                data.append(" ");
                data.append(argv[i]);
        }
        int len = data.size();
        

        int sd = connection (address, port);
        if (sd == -1) {
                cout<<"Client: Unable to connect to server\n";
                exit(1);
        }

        int fd = open("log_client", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        close(fd);
        Protocol prt(CLIENT, "log_client");

        int ret;

        // key exchange
        ret = prt.send_message(sd, M1);
        if (ret == -1) {
                cout<<"Client: Key exchange failed!\n";
                close(sd);
                exit(1);
        }
        ret = prt.receive_message(sd, M2);
        if (ret == -1) {
                cout<<"Client: Key exchange failed!\n";
                close(sd);
                exit(1);
        }
        ret = prt.send_message(sd, M3);
        if (ret == -1) {
                cout<<"Client: Key exchange failed!\n";
                close(sd);
                exit(1);
        }

        // send data
        ret = prt.send_data(sd, (char *) data.c_str(), len);
        if (ret == -1) {
                cout<<"Client: Unable to send data to server\n";
                close(sd);
                exit(1);
        }

        close(sd);
        exit(0);
}
