#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 8080
#define IP_ADDR "192.168.10.1"
#define BUFFER_SIZE 1024

int main() {
    //sleep(5);
    // Создание файлов
    FILE *file1 = fopen("file1.txt", "w");
    printf("Ya vstal pered file1\n");
    if (file1 == NULL) {
        printf("Ошибка создания файла file1.txt\n");
        return 1;
    }
    fclose(file1);
    printf("Ya vstal pered file2\n");
    FILE *file2 = fopen("file2.txt", "w");
    if (file2 == NULL) {
        printf("Ошибка создания файла file2.txt\n");
        return 1;
    }
    fclose(file2);
    printf("Ya vstal pered file1 open\n");
    // Открытие файлов
    file1 = fopen("file1.txt", "r");
    if (file1 == NULL) {
        printf("Ошибка открытия файла file1.txt\n");
        return 1;
    }
    fclose(file1);

    file2 = fopen("file2.txt", "r");
    printf("Ya vstal pered file2 open\n");
    if (file2 == NULL) {
        printf("Ошибка открытия файла file2.txt\n");
        return 1;
    }
    fclose(file2);
    printf("Ya vstal pered socket creation\n");
    // Попытка установить TCP-соединение
    int sockfd;
    struct sockaddr_in servaddr;
    printf("Ya vstal pered socket creation2\n");
    // Создание сокета
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("Ошибка создания сокета\n");
        return 1;
    }
    printf("Ya vstal pered sockaddr_in\n");
    // Заполнение структуры sockaddr_in
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(IP_ADDR);
    servaddr.sin_port = htons(PORT);
    printf("Ya vstal pered connect\n");
    // Попытка установить соединение
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1) {
        printf("Ошибка установки соединения\n");
        close(sockfd);
        return 1;
    }

    printf("Соединение установлено\n");

    // Отправка нескольких простых пакетов
    char buffer[BUFFER_SIZE];
    strcpy(buffer, "Hello, server!");
    send(sockfd, buffer, strlen(buffer), 0);
    sleep(2);
    strcpy(buffer, "This is a test packet.");
    send(sockfd, buffer, strlen(buffer), 0);
    sleep(2);
    strcpy(buffer, "Goodbye!");
    send(sockfd, buffer, strlen(buffer), 0);

    close(sockfd);

    return 0;
}
