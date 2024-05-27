#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define PING_COUNT 5  // Количество пингов

int main() {
    struct sockaddr_in server_addr;
    struct hostent *host_info;
    int sock, count;
    char buffer[1024];

    // Получение информации о хосте
    host_info = gethostbyname("google.com");
    if (host_info == NULL) {
        fprintf(stderr, "Ошибка получения информации о хосте\n");
        return 1;
    }

    // Создание сокета
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        fprintf(stderr, "Ошибка создания сокета\n");
        return 1;
    }

    // Заполнение структуры sockaddr_in
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);  // HTTP порт
    memcpy(&server_addr.sin_addr, host_info->h_addr_list[0], host_info->h_length);

    // Пинг ya.ru несколько раз
    for (count = 0; count < PING_COUNT; count++) {
        // Попытка установить соединение
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
            fprintf(stderr, "Ошибка соединения\n");
            close(sock);
            return 1;
        }

        // Отправка HTTP-запроса
        sprintf(buffer, "GET / HTTP/1.1\r\nHost: ya.ru\r\n\r\n");
        send(sock, buffer, strlen(buffer), 0);

        // Получение ответа
        memset(buffer, 0, sizeof(buffer));
        recv(sock, buffer, sizeof(buffer) - 1, 0);

        printf("Пинг %d: Успешно\n", count + 1);

        // Закрытие соединения
        close(sock);

        // Задержка перед следующим пингом
        sleep(1);
    }

    return 0;
}
