#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Создание сокета
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Ошибка создания сокета");
        exit(EXIT_FAILURE);
    }

    // Установка опции для повторного использования адреса
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Ошибка установки опции сокета");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(PORT);

    // Привязка сокета к адресу и порту
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Ошибка привязки сокета");
        exit(EXIT_FAILURE);
    }

    // Прослушивание входящих соединений
    if (listen(server_fd, 3) < 0) {
        perror("Ошибка прослушивания");
        exit(EXIT_FAILURE);
    }

    printf("Сервер запущен на порту %d\n", PORT);

    while (1) {
        // Принятие входящего соединения
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Ошибка принятия соединения");
            exit(EXIT_FAILURE);
        }

        // Получение сообщения от клиента
        memset(buffer, 0, BUFFER_SIZE);
        int valread = read(new_socket, buffer, BUFFER_SIZE);
        if (valread > 0) {
            printf("Получено сообщение: %s\n", buffer);
        } else {
            printf("Ошибка чтения сообщения\n");
        }

        // Закрытие соединения с клиентом
        //close(new_socket);
    }

    // Закрытие сокета сервера
    close(server_fd);

    return 0;
}
