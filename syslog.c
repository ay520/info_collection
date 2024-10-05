#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h> // 包含 getaddrinfo
#define SYSLOG_PORT "514" // 使用字符串形式的端口
#define SYSLOG_SERVER "your.syslog.server.com" // 替换为你的 syslog 服务器域名
#define SYSLOG_MAX_LENGTH (1024 * 5000)
#define facility 16 //local0,syslog 自定义类型的日志，从local0～local7
#define severity 6


void send_log_via_syslog(const char *message, const char *hostname, const char *tag) {
    int sock;
    struct addrinfo hints, *res, *p;

    // 初始化 hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // 支持IPv4和IPv6
    hints.ai_socktype = SOCK_STREAM;

    // 获取服务器地址信息
    if (getaddrinfo(SYSLOG_SERVER, SYSLOG_PORT, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    // 创建 socket 并连接到服务器
    for (p = res; p != NULL; p = p->ai_next) {
        // 创建 TCP socket
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) {
            perror("socket");
            continue; // 尝试下一个地址
        }

        // 连接到服务器
        if (connect(sock, p->ai_addr, p->ai_addrlen) < 0) {
            perror("connect");
            close(sock);
            continue; // 尝试下一个地址
        }

        break; // 成功连接
    }

    // 检查是否成功连接到任何地址
    if (p == NULL) {
        fprintf(stderr, "Failed to connect to any address\n");
        exit(EXIT_FAILURE);
    }

    // 动态分配最大的 syslog 消息长度
    size_t max_msg_length = SYSLOG_MAX_LENGTH; // 预留足够空间
    char *syslog_message = malloc(max_msg_length);
    if (syslog_message == NULL) {
        perror("malloc");
        close(sock);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    // 获取当前时间戳
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32]; // 格式化时间的缓冲区，有足够的空间
    strftime(timestamp, sizeof(timestamp), "%b %d %H:%M:%S", tm_info);

    // 构造 syslog 消息
    int priority = (facility * 8) + severity; // 计算优先级
    snprintf(syslog_message, max_msg_length, "<%d>%s [%s][%s]: %s\n", 
             priority, timestamp, hostname, tag, message); // 使用动态传入的 HOSTNAME 和 TAG

    // 发送 syslog 消息
    ssize_t send_result = send(sock, syslog_message, strlen(syslog_message), 0);
    if (send_result < 0) {
        perror("send");
        free(syslog_message); // 确保释放内存
        close(sock);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    // 关闭 socket 和释放动态分配的内存
    free(syslog_message);
    close(sock);
    freeaddrinfo(res);
}

/*
int main() {
    // 示例调用
    send_log_via_syslog("This is a test log message.", "myhost.local", "myapp", 16, 6); // 传入动态 HOSTNAME 和 TAG
    return 0;
}

*/