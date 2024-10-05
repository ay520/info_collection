#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "include/cJSON.h"

#define BUFFER_SIZE 8192
#define SOCK_DIAG_BY_FAMILY 20
#define TCPF_ALL 0xFFF



typedef struct connection {
    uint32_t inode;
    union {
        struct sockaddr_in local_addr;    // IPv4
        struct sockaddr_in6 local_addr6;  // IPv6
    };
    union {
        struct sockaddr_in remote_addr;   // IPv4
        struct sockaddr_in6 remote_addr6; // IPv6
    };
    char proto_name[16];
    int pid;
    int state;               // 状态
    int is_ipv6;            // 标识连接是否为IPv6
    char state_desc[32];    // 状态描述
} connection_t;

// 状态翻译函数
const char* translate_state(int state) {
    // Manually define the TCP states using enum
    enum {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT=2,
        TCP_SYN_RECV=3,
        TCP_FIN_WAIT1=4,
        TCP_FIN_WAIT2=5,
        TCP_TIME_WAIT=6,
        TCP_CLOSE=7,
        TCP_CLOSE_WAIT=8,
        TCP_LAST_ACK=9,
        TCP_LISTEN=10,
        TCP_CLOSING=11
    };
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSED";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

int get_pid_by_inode(uint32_t inode) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir");
        return -1;
    }
    struct dirent *proc_entry;
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        if (proc_entry->d_type == DT_DIR) {
            int pid = atoi(proc_entry->d_name);
            if (pid <= 0) continue;
            char fd_path[256];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
            DIR *fd_dir = opendir(fd_path);
            if (fd_dir == NULL) continue;
            struct dirent *fd_entry;
            while ((fd_entry = readdir(fd_dir)) != NULL) {
                if (fd_entry->d_type == DT_LNK) {
                    char link_path[256];
                    snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
                    struct stat stat_buf;
                    if (stat(link_path, &stat_buf) == 0) {
                        if (stat_buf.st_ino == inode) {
                            closedir(fd_dir);
                            closedir(proc_dir);
                            return pid;
                        }
                    }
                }
            }
            closedir(fd_dir);
        }
    }
    closedir(proc_dir);
    return -1;
}

int get_connections(connection_t **connections, size_t *num_connections, int protocol) {
    int sock;
    struct sockaddr_nl sa;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh;
    char buffer[BUFFER_SIZE];
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct inet_diag_req_v2 req;
    memset(&req, 0, sizeof(req));
    req.sdiag_family = (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) ? (protocol == IPPROTO_TCP ? AF_INET : AF_INET6) : 0;
    req.sdiag_protocol = protocol;
    req.idiag_states = TCPF_ALL;

    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    memcpy(NLMSG_DATA(nlh), &req, sizeof(req));

    iov.iov_base = buffer;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sock, &msg, 0) < 0) {
        perror("sendmsg");
        close(sock);
        return -1;
    }

    *connections = NULL;
    *num_connections = 0;
    size_t buffer_size = 1024;
    *connections = malloc(buffer_size * sizeof(connection_t));
    if (*connections == NULL) {
        perror("Memory allocation failed");
        close(sock);
        return -1;
    }

    while (1) {
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("recv");
            free(*connections);
            close(sock);
            return -1;
        }
        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                break;
            }
            if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                struct inet_diag_msg *diag_msg = NLMSG_DATA(nlh);
                if (*num_connections >= buffer_size) {
                    buffer_size *= 2;
                    *connections = realloc(*connections, buffer_size * sizeof(connection_t));
                    if (*connections == NULL) {
                        perror("Memory reallocation failed");
                        close(sock);
                        return -1;
                    }
                }

                (*connections)[*num_connections].inode = diag_msg->idiag_inode;
                if (diag_msg->idiag_family == AF_INET) { // IPv4
                    struct sockaddr_in *local_addr = (struct sockaddr_in *)&(*connections)[*num_connections].local_addr;
                    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&(*connections)[*num_connections].remote_addr;
                    local_addr->sin_family = AF_INET;
                    memcpy(&local_addr->sin_addr, &diag_msg->id.idiag_src, sizeof(local_addr->sin_addr));
                    local_addr->sin_port = diag_msg->id.idiag_sport;
                    remote_addr->sin_family = AF_INET;
                    memcpy(&remote_addr->sin_addr, &diag_msg->id.idiag_dst, sizeof(remote_addr->sin_addr));
                    remote_addr->sin_port = diag_msg->id.idiag_dport;
                    (*connections)[*num_connections].is_ipv6 = 0;
                } else if (diag_msg->idiag_family == AF_INET6) { // IPv6
                    struct sockaddr_in6 *local_addr6 = (struct sockaddr_in6 *)&(*connections)[*num_connections].local_addr6;
                    struct sockaddr_in6 *remote_addr6 = (struct sockaddr_in6 *)&(*connections)[*num_connections].remote_addr6;
                    local_addr6->sin6_family = AF_INET6;
                    memcpy(&local_addr6->sin6_addr, diag_msg->id.idiag_src, sizeof(struct in6_addr));
                    local_addr6->sin6_port = diag_msg->id.idiag_sport;
                    remote_addr6->sin6_family = AF_INET6;
                    memcpy(&remote_addr6->sin6_addr, diag_msg->id.idiag_dst, sizeof(struct in6_addr));
                    remote_addr6->sin6_port = diag_msg->id.idiag_dport;
                    (*connections)[*num_connections].is_ipv6 = 1;
                }

                strncpy((*connections)[*num_connections].proto_name,
                        protocol == IPPROTO_TCP ? "TCP" : "UDP", sizeof((*connections)[*num_connections].proto_name));
                (*connections)[*num_connections].pid = -1;
                (*connections)[*num_connections].state = diag_msg->idiag_state;
                strncpy((*connections)[*num_connections].state_desc, translate_state(diag_msg->idiag_state), sizeof((*connections)[*num_connections].state_desc));
                (*num_connections)++;
            }
        }
        if (nlh->nlmsg_type == NLMSG_DONE) {
            break;
        }
    }

    close(sock);
    return 0;
}

void print_connections_as_json(connection_t *connections, size_t num_connections,cJSON *json_array) {

   

    // printf("[\n");
    for (size_t i = 0; i < num_connections; i++) {
        char local_addr[INET6_ADDRSTRLEN];
        char remote_addr[INET6_ADDRSTRLEN];
         cJSON *json_item = cJSON_CreateObject();
    
        if (connections[i].is_ipv6) {
            inet_ntop(AF_INET6, &connections[i].local_addr6.sin6_addr, local_addr, sizeof(local_addr));
            inet_ntop(AF_INET6, &connections[i].remote_addr6.sin6_addr, remote_addr, sizeof(remote_addr));

            cJSON_AddStringToObject(json_item, "Protocol", connections[i].proto_name);
            cJSON_AddStringToObject(json_item, "local_addr", local_addr);
            cJSON_AddNumberToObject(json_item, "local_port", ntohs(connections[i].local_addr6.sin6_port));
            cJSON_AddStringToObject(json_item, "remote_addr",remote_addr);
            cJSON_AddNumberToObject(json_item, "remote_port", ntohs(connections[i].remote_addr6.sin6_port));
            cJSON_AddNumberToObject(json_item, "PID", connections[i].pid);
            cJSON_AddStringToObject(json_item, "State", connections[i].state_desc);
            cJSON_AddNumberToObject(json_item, "Inode", connections[i].inode);
            cJSON_AddStringToObject(json_item, "IPType", "ipv6");

            // printf("    {\n");
            // printf("        \"Protocol\": \"%s\",\n", connections[i].proto_name);
            // printf("        \"Local\": \"[%s]:%d\",\n", local_addr, ntohs(connections[i].local_addr6.sin6_port));
            // printf("        \"Remote\": \"[%s]:%d\",\n", remote_addr, ntohs(connections[i].remote_addr6.sin6_port));
            // printf("        \"PID\": %d,\n", connections[i].pid);
            // printf("        \"State\": \"%s\",\n", connections[i].state_desc);
            // printf("        \"Inode\": %u,\n", connections[i].inode);
            // printf("        \"IPType\": \"v6\"\n");
        } else {
            inet_ntop(AF_INET, &connections[i].local_addr.sin_addr, local_addr, sizeof(local_addr));
            inet_ntop(AF_INET, &connections[i].remote_addr.sin_addr, remote_addr, sizeof(remote_addr));
            cJSON_AddStringToObject(json_item, "Protocol", connections[i].proto_name);
            cJSON_AddStringToObject(json_item, "local_addr", local_addr);
            cJSON_AddNumberToObject(json_item, "local_port",  ntohs(connections[i].local_addr.sin_port));
            cJSON_AddStringToObject(json_item, "remote_addr",remote_addr);
            cJSON_AddNumberToObject(json_item, "remote_port", ntohs(connections[i].remote_addr.sin_port));
            cJSON_AddNumberToObject(json_item, "PID", connections[i].pid);
            cJSON_AddStringToObject(json_item, "State", connections[i].state_desc);
            cJSON_AddNumberToObject(json_item, "Inode", connections[i].inode);
            cJSON_AddStringToObject(json_item, "IPType", "ipv4");

            // printf("        \"Protocol\": \"%s\",\n", connections[i].proto_name);
            // printf("        \"Local\": \"%s:%d\",\n", local_addr, ntohs(connections[i].local_addr.sin_port));
            // printf("        \"Remote\": \"%s:%d\",\n", remote_addr, ntohs(connections[i].remote_addr.sin_port));
            // printf("        \"PID\": %d,\n", connections[i].pid);
            // printf("        \"State\": \"%s\",\n", connections[i].state_desc);
            // printf("        \"Inode\": %u,\n", connections[i].inode);
            // printf("        \"IPType\": \"v4\"\n");
        
        }
        // printf("    }%s\n", (i == num_connections - 1) ? "" : ",");
        cJSON_AddItemToArray(json_array, json_item);
    }
    // printf("]\n");
   
}

char * get_connections_result()
 {
    connection_t *tcp_connections = NULL;
    connection_t *udp_connections = NULL;
    size_t num_tcp_connections = 0;
    size_t num_udp_connections = 0;

    char * error_msg=NULL;

    if (get_connections(&tcp_connections, &num_tcp_connections, IPPROTO_TCP) < 0) {
        perror("Failed to get TCP connections");
        sprintf(error_msg,"Failed to get TCP connections");
        return error_msg;
    }
    if (get_connections(&udp_connections, &num_udp_connections, IPPROTO_UDP) < 0) {
        perror("Failed to get UDP connections");
        sprintf(error_msg,"Failed to get UDP connections");
        return error_msg;
    }

    // Filling PIDs for the connections
    for (size_t i = 0; i < num_tcp_connections; i++) {
        tcp_connections[i].pid = get_pid_by_inode(tcp_connections[i].inode);
    }
    for (size_t i = 0; i < num_udp_connections; i++) {
        udp_connections[i].pid = get_pid_by_inode(udp_connections[i].inode);
    }



    cJSON *json_array = cJSON_CreateArray();
    print_connections_as_json(tcp_connections, num_tcp_connections,json_array);
    print_connections_as_json(udp_connections, num_udp_connections,json_array);

    char *json_output = cJSON_PrintUnformatted(json_array);
    cJSON_Delete(json_array);


    free(tcp_connections);
    free(udp_connections);

    // printf("%s",json_output);
    return json_output;
}



/*
int main() {
    connection_t *tcp_connections = NULL;
    connection_t *udp_connections = NULL;
    size_t num_tcp_connections = 0;
    size_t num_udp_connections = 0;

    if (get_connections(&tcp_connections, &num_tcp_connections, IPPROTO_TCP) < 0) {
        perror("Failed to get TCP connections");
        return EXIT_FAILURE;
    }
    if (get_connections(&udp_connections, &num_udp_connections, IPPROTO_UDP) < 0) {
        perror("Failed to get UDP connections");
        return EXIT_FAILURE;
    }

    // Filling PIDs for the connections
    for (size_t i = 0; i < num_tcp_connections; i++) {
        tcp_connections[i].pid = get_pid_by_inode(tcp_connections[i].inode);
    }
    for (size_t i = 0; i < num_udp_connections; i++) {
        udp_connections[i].pid = get_pid_by_inode(udp_connections[i].inode);
    }



    cJSON *json_array = cJSON_CreateArray();
    print_connections_as_json(tcp_connections, num_tcp_connections,json_array);
    print_connections_as_json(udp_connections, num_udp_connections,json_array);

    char *json_output = cJSON_PrintUnformatted(json_array);
    cJSON_Delete(json_array);


    free(tcp_connections);
    free(udp_connections);

    printf("%s",json_output);
    return EXIT_SUCCESS;
}
*/