#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>

/* Este é um exemplo de código em C de baixa latência
 * para consumo em IPv4 por UDP do serviço WhoisCacheServer.
 *
 * Altere este código para servir da melhor
 * forma possível seus propósitos.
 */

#define BUFLEN 512 // Max length of buffer.

void help() {
    puts("Use command:");
    puts("  whoiscc <ip> <port> <query>");
    puts("");
    puts("  ip: server IPv4.");
    puts("  port: server port 1-65535.");
    puts("  query: query command to server delimited by '\"'.");
    puts("");
    puts("Output codes:");
    puts("0. Result success.");
    puts("1. Invalid arguments.");
    puts("2. Invalid UPD port.");
    puts("3. Bind socket error.");
    puts("4. Invalid IP address.");
    puts("5. Query packet error.");
    puts("6. Result packet error.");
    puts("7. Result error.");
}

int prefix(const char *pre, const char *str) {
    return strncmp(pre, str, strlen(pre)) == 0;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {

        help();
        return 1;

    }

    struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other);
    char buf[BUFLEN];

    char *server = argv[1];
    int port = atoi(argv[2]);
    char *message = argv[3];

    if (port < 1 || port > 65535) {

        perror("ERROR: UDP PORT");
        return 2; // Invalid UPD port.

    }

    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {

        perror("ERROR: BIND SOCKET");
        return 3; // Bind socket error.

    }

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(port);

    if (inet_aton(server , &si_other.sin_addr) == 0) {
        perror("ERROR: IP ADDRESS");
        return 4; // Invalid IP address.
    }

    // Send the query packet.
    if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1) {

        perror("ERROR: QUERY PACKET");
        return 5; // Query packet error.

    }

    // Receive the result packet.
    memset(buf,'\0', BUFLEN);
    // Try to receive some data, this is a blocking call.
    if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1) {

        perror("ERROR: RESULT PACKET");
        return 6; // Result packet error.

    }

    // Close socket.
    close(s);

    if (prefix("ERROR: ", buf)) {

        perror(buf);
        return 7; // Result error.

    } else {

        printf(buf);
        return 0;

    }
}
