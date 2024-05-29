#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PING_COUNT 5

int main() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        std::cerr << "Ptrace error" << std::endl;
        return 1;
    }

    std::cout << "Doing something..." << std::endl;

    int status;
    waitpid(-1, &status, 0);

    if (WIFSTOPPED(status)) {
        std::cout << "Program is under debug!" << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    struct hostent *host_info;
    int sock, count;
    char buffer[1024];

    host_info = gethostbyname("google.com");
    if (host_info == NULL) {
        fprintf(stderr, "Error getting hostname\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        fprintf(stderr, "Error creating socket\n");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    memcpy(&server_addr.sin_addr, host_info->h_addr_list[0], host_info->h_length);

    for (count = 0; count < PING_COUNT; count++) {
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
            fprintf(stderr, "Connection error\n");
            close(sock);
            return 1;
        }

        sprintf(buffer, "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n");
        send(sock, buffer, strlen(buffer), 0);

        memset(buffer, 0, sizeof(buffer));
        recv(sock, buffer, sizeof(buffer) - 1, 0);

        printf("Ping %d: Success\n", count + 1);

        //close(sock);

        sleep(1);
    }

    std::cout << "End of program" << std::endl;

    return 0;
}