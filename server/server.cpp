/** 
 * @file server.cpp
 * @brief Simple Server for testing key exchange protocol.
 *
 * @author Valerio Luconi
 * @version 1.0
 */

#include "../protocol/protocol.h"

#define BACKLOG 10

/**
 * Initializes server for listening.
 * @param[in]   port Server listening port.
 * @return      A valid listening socket on success, -1 on failure.
 */
int connection (int port)
{
        int sd = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in address;
        bzero(&address, sizeof(sockaddr_in));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        int ret = bind(sd, (sockaddr *) &address, sizeof(sockaddr_in));
        if (ret == -1)
                return ret;

        ret = listen(sd, BACKLOG);
        if (ret == -1)
                return ret;

        return sd;
}

/**
 * Child process, handles Key exchange and Data exchange.
 * @param[in]   csd A valid socket connected with client.
 * @param[in]   ssd Listening socket to be closed.
 * @return      0 on success, -1 on failure.
 */
int child (int csd, int ssd)
{
        int ret;
        close(ssd);

        int fd = open("log_server", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        close(fd);
        Protocol prt(SERVER, "log_server");

        // key exchange
        ret = prt.receive_message(csd, M1);
        if (ret == -1) {
                cout<<"Server: Key exchange failed!\n";
                close(csd);
                return -1;
        }
        ret = prt.send_message(csd, M2);
        if (ret == -1) {
                cout<<"Server: Key exchange failed!\n";
                close(csd);
                return -1;
        }
        ret = prt.receive_message(csd, M3);
        if (ret == -1) {
                cout<<"Server: Key exchange failed!\n";
                close(csd);
                return -1;
        }

        // receive data
        char *data;
        int len;
        ret = prt.receive_data(csd, data, &len);
        if (ret == -1) {
                cout<<"Server: Unable to receive data from client\n";
                close(csd);
                return -1;
        }
        cout<<"Server: Data Received\n\t";
        for (int i = 0; i < len; i++)
                cout<<data[i];
        cout<<"\n\n";

        close(csd);
        return 0;
}

/**
 * Main function.
 * @param[in]   argc Number of arguments.
 * @param[in]   argv[0] Program name.
 * @param[in]   argv[1] Listening port.
 */
int main(int argc, char *argv[])
{
        if (argc != 2) {
                cout<<"Server: Bad arguments\nSyntax:\n./server port\n";
                exit(1);
        }

        int port = atoi(argv[1]);

        int ssd = connection(port);
        if (ssd == -1) {
                cout<<"Server: Unable to initialize connection\n";
                exit(1);
        }

        sockaddr_in cl_addr;
        
        while (1) {
                int len = sizeof(cl_addr);
                int csd = accept(ssd, (sockaddr *) &cl_addr, (socklen_t *) &len);

                int pid = fork();

                if (pid == 0) {
                        int ret = child(csd, ssd);
                        if (ret == -1)
                                exit(1);
                        exit(0);
                }

                close(csd);
        }
        close(ssd);
        exit(0);
}
