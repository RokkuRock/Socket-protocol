#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        exit(0);
    }

    char* server_ip = argv[1];
    int port = atoi(argv[2]);

    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in serverAddr;
    char buffer[1024];
    int addrSize, n;

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("[-]Failed to initialize winsock");
        exit(1);
    }

    // 創建Socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        perror("[-]Failed to create socket");
        exit(1);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(server_ip);

    bzero(buffer, 1024);
    strcpy(buffer, "Call from windows Client 1!");
    sendto(sockfd, buffer, 1024, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    printf("[+]Data send: %s\n", buffer);

    bzero(buffer, 1024);
    addrSize = sizeof(serverAddr);
    recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr*)&serverAddr, &addrSize);
    printf("[+]Data recv: %s\n", buffer);

    closesocket(sockfd);
    WSACleanup();

    return 0;
}
