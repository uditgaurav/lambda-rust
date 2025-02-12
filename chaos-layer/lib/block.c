// block.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

typedef int (*orig_connect_type)(int, const struct sockaddr *, socklen_t);

// Structure to hold blocked IP:port pairs
struct BlockedEntry {
    char ip[INET6_ADDRSTRLEN];
    int port;
};
static struct BlockedEntry *blocked_entries = NULL;
static size_t num_blocked = 0;

// Parse BLOCKED_HOSTS from environment variable
void parse_blocked_hosts() {
    const char *blocked_hosts = getenv("BLOCKED_HOSTS");
    if (!blocked_hosts) return;

    char *entries = strdup(blocked_hosts);
    char *token = strtok(entries, ",");
    while (token) {
        char *host_part = token;
        char *port_part = strchr(token, ':');
        int port = 0;
        if (port_part) {
            *port_part = '\0';
            port = atoi(port_part + 1);
            host_part = token;
        }

        // Resolve host to IP(s)
        struct addrinfo hints = {0}, *result;
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host_part, NULL, &hints, &result) == 0) {
            for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
                char ip[INET6_ADDRSTRLEN];
                void *addr;
                if (rp->ai_family == AF_INET) {
                    addr = &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
                } else {
                    addr = &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
                }
                inet_ntop(rp->ai_family, addr, ip, sizeof(ip));

                // Add to blocked entries
                blocked_entries = realloc(blocked_entries, (num_blocked + 1) * sizeof(struct BlockedEntry));
                strncpy(blocked_entries[num_blocked].ip, ip, INET6_ADDRSTRLEN);
                blocked_entries[num_blocked].port = port;
                num_blocked++;
            }
            freeaddrinfo(result);
        }
        token = strtok(NULL, ",");
    }
    free(entries);
}

// Override connect()
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static orig_connect_type orig_connect = NULL;
    if (!orig_connect) {
        orig_connect = (orig_connect_type)dlsym(RTLD_NEXT, "connect");
        parse_blocked_hosts(); // Parse on first call
    }

    // Extract destination IP and port
    char ip[INET6_ADDRSTRLEN];
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
        port = ntohs(addr_in->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip));
        port = ntohs(addr_in6->sin6_port);
    }

    // Check against blocked entries
    for (size_t i = 0; i < num_blocked; i++) {
        if (strcmp(blocked_entries[i].ip, ip) == 0 &&
            (blocked_entries[i].port == 0 || blocked_entries[i].port == port)) {
            errno = ECONNREFUSED; // Simulate connection failure
            return -1;
        }
    }

    return orig_connect(sockfd, addr, addrlen);
}
