#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define TIMEOUT_SECONDS 60

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);

    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in serverAddr;

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
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // 綁定Socket
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("[-]Bind failed");
        exit(1);
    }

    // 接收訊息
    char buffer[1024];
    struct sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    int bytesReceived;

    // 開始計時
    clock_t start_time, current_time;
    double elapsed_time;
    start_time = clock();

    // 等待訊息或超時
    while (1) {
        current_time = clock();
        elapsed_time = (double)(current_time - start_time) / CLOCKS_PER_SEC;

        if (elapsed_time >= TIMEOUT_SECONDS) {
            printf("1-min TIMEOUT, No messages received\n");
            break;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        int result = select(0, &fds, NULL, NULL, &tv);
        if (result > 0 && FD_ISSET(sockfd, &fds)) {
            bytesReceived = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddr, &addrLen);
            if (bytesReceived > 0) {
                printf("[+]Data recv: %s\n", buffer);

                // 回覆訊息
                char replyBuffer[1024];
                strcpy(replyBuffer, "Welcome to the Windows UDP Server.");
                sendto(sockfd, replyBuffer, strlen(replyBuffer) + 1, 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
                printf("[+]Data send: %s\n", replyBuffer);

                // 重新計時
                start_time = clock();
            }
        }
    }

    // 關閉Socket
    closesocket(sockfd);
    WSACleanup();

    return 0;
}