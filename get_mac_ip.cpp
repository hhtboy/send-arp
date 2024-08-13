#include "get_mac_ip.h"
#include <cstdio>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void get_mac_address(const char *interface, char *mac_str, size_t buf_size) {
    int fd;
    struct ifreq ifr;
    unsigned char *mac;

    if (buf_size < 18) { 
        fprintf(stderr, "Buffer size too small\n");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    snprintf(mac_str, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);

    close(fd);
}

void get_ip_address(const char *interface, char *ip_str, size_t buf_size) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    if (buf_size < INET_ADDRSTRLEN) { 
        fprintf(stderr, "Buffer size too small\n");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    addr = (struct sockaddr_in *)&ifr.ifr_addr;

    if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, buf_size) == NULL) {
        perror("inet_ntop");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}
