#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/utsname.h>
#include "include/cJSON.h"
#include "hostuuid.c"

#ifndef	IFF_PROMISC
#define IFF_PROMISC 0x100
#endif

#define route_conf_path "/proc/net/route"
#define ipv6_route_path "/proc/net/ipv6_route"
#define resolv_conf_path "/etc/resolv.conf"
#define osversion_conf_path "/etc/os-release"


// Function declarations
int check_promiscuous_mode(const char *iface);
// cJSON *get_default_gateways();
cJSON *get_dns_servers();
char *get_os_info();
char *get_kernel_version();
cJSON *get_ip_addresses();
char *get_hostname_ip_json();
void  get_v4_default_gateway(const char *iface_name, char *gateway);
void  get_v6_default_gateway(const char *iface_name, char *gateway);

int check_promiscuous_mode(const char *iface) {
    FILE *fp;
    int flags;

    char interface_path[256] = {0};
    sprintf(interface_path, "/sys/class/net/%s/flags", iface);

    fp = fopen(interface_path, "r");
    if (fp == NULL) {
        perror("Error opening file");
        return -1;
    }
    if (fscanf(fp, "%x", &flags) != 1) {
        perror("Error reading file");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return (flags & IFF_PROMISC) ? 1 : 0;
}

//十六进制转成标准可读IPv6
void hex_to_ipv6(const char *hex_ip,char * ipv6_str) {
    struct in6_addr ipv6_addr;

    // 将十六进制字符串转换为二进制格式
    for (int i = 0; i < 16; i++) {
        sscanf(hex_ip + (i * 2), "%2hhx", &ipv6_addr.s6_addr[i]);
    }

    // 转换为标准可读格式
    char str_ip[INET6_ADDRSTRLEN]; // 适合IPv6地址最大长度
    if (inet_ntop(AF_INET6, &ipv6_addr, str_ip, sizeof(str_ip)) == NULL) {
        perror("inet_ntop");
        return;
    }

    sprintf(ipv6_str,"%s",str_ip);
    return ;
}

// Function to collect both IPv4 and IPv6 gateways
void  get_v4_default_gateway(const char *iface_name, char *gateway) {
 
    // Collect IPv4 gateways
    FILE *fp = fopen(route_conf_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return ;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {

        if (strncmp(line, "Iface", 5) == 0) continue; //跳过第一行 为表头

        uint32_t dest, gw;
        char iface[16];

        int ret = sscanf(line, "%s\t%X\t%X", iface, &dest, &gw);
        if (ret == 3 && dest == 0 && gw != 0 && strcmp(iface,iface_name)==0 ) {
            // printf("iface:%s,iface_name:%s\n",iface,iface_name);
            struct in_addr addr;
            addr.s_addr = gw;
            sprintf(gateway,"%s",inet_ntoa(addr));
            break;       
        }
    }
    fclose(fp);
    
    return;
}


    // Collect IPv6 gateways from /proc/net/ipv6_route
void  get_v6_default_gateway(const char *iface_name, char *gateway) {

    sprintf(gateway,"%s","N/A");

    FILE *fp = fopen(ipv6_route_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return;
    }

    char line[256]; int conf_type=0;
    while (fgets(line, sizeof(line), fp) != NULL) {

        if (strncmp(line, "Destination", 11) == 0) {
            conf_type=1;
            continue; //跳过第一行 为表头
        }
        char dest[INET6_ADDRSTRLEN]={0}, next_hop[INET6_ADDRSTRLEN]={0},Iface[IF_NAMESIZE]={0};
        int prefix_len;

        // 尝试使用标准 IPv6 路由格式解析
        if(conf_type){
            if (sscanf(line, "%32s %2x %32s %32s", dest, &prefix_len, next_hop,Iface) == 4) {
                printf("dest:%s,next_hop:%s,Iface:%s\n",dest, next_hop,Iface);
                if (strcmp(Iface, "lo") == 0) continue;
                if (strcmp(dest, "::/0") == 0 &&  strcmp(iface_name,Iface)==0) { // 标准默认路由

                    sprintf(gateway,"%s",next_hop);
                    return;
                }
            } 
        }else {
            // 处理提供的多播地址格式
            char multi_dest[33], multi_next_hop[33],multi_iface[33], ipv6_str[INET6_ADDRSTRLEN];
            if (sscanf(line, "%32s %*s %32s %*s %*s %*s %*s %*s %*s %32s", multi_dest, multi_next_hop,multi_iface) == 3) {
                if (strcmp(multi_iface, "lo") == 0) continue;
                // printf("multi_dest:%s,multi_next_hop:%s, multi_iface:%s\n",multi_dest, multi_next_hop,multi_iface);
                if (strcmp(multi_dest, "00000000000000000000000000000000") == 0 &&  strcmp(iface_name,multi_iface)==0) {
                    
                    hex_to_ipv6(multi_next_hop,ipv6_str);
                    sprintf(gateway,"%s",ipv6_str);
                    return;
                }
            }
        }
    }
    fclose(fp);


   return;
}

// Function to collect both IPv4 and IPv6 gateways
/*
cJSON *get_default_gateways() {
    cJSON *gateways = cJSON_CreateObject();
    if (gateways == NULL) return NULL;

    // Collect IPv4 gateways
    FILE *fp = fopen(route_conf_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    cJSON *ipv4_gateways = cJSON_CreateArray();
    char line[256];

    while (fgets(line, sizeof(line), fp) != NULL) {
        uint32_t dest, gw;
        char iface[16];
        int ret = sscanf(line, "%s\t%X\t%X", iface, &dest, &gw);
        if (ret == 3 && dest == 0 && gw != 0) {
            struct in_addr addr;
            addr.s_addr = gw;
            cJSON *g = cJSON_CreateString(inet_ntoa(addr));
            cJSON_AddItemToArray(ipv4_gateways, g);
        }
    }
    fclose(fp);
    cJSON_AddItemToObject(gateways, "IPv4", ipv4_gateways);

    // Collect IPv6 gateways from /proc/net/ipv6_route
    fp = fopen(ipv6_route_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    cJSON *ipv6_gateways = cJSON_CreateArray();
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        char dest[INET6_ADDRSTRLEN], next_hop[INET6_ADDRSTRLEN];
        int prefix_len;

        // 尝试使用标准 IPv6 路由格式解析
        if (sscanf(line, "%32s %2x %32s", dest, &prefix_len, next_hop) >= 3) {
            // printf("dest:%s,next_hop:%s",dest, next_hop);
            if (strcmp(dest, "::/0") == 0) { // 标准默认路由
                cJSON *g = cJSON_CreateString(next_hop);
                cJSON_AddItemToArray(ipv6_gateways, g);
            }
        } else {
            // 处理提供的多播地址格式
            char multi_dest[33], multi_next_hop[33];
            if (sscanf(line, "%32s %*s %32s", multi_dest, multi_next_hop) == 2) {
                // printf("multi_dest:%s,multi_next_hop:%s",multi_dest, multi_next_hop);
                if (strcmp(multi_dest, "ff000000000000000000000000000000") == 0) {
                    cJSON *g = cJSON_CreateString(multi_next_hop);
                    cJSON_AddItemToArray(ipv6_gateways, g);
                }
            }
        }
    }
    fclose(fp);
    cJSON_AddItemToObject(gateways, "IPv6", ipv6_gateways);

    return gateways;
}
*/

cJSON *get_dns_servers() {
    FILE *fp = fopen(resolv_conf_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    cJSON *dns_servers = cJSON_CreateArray();
    char line[256];

    while (fgets(line, sizeof(line), fp) != NULL) {
        char ns[128];
        if (sscanf(line, "nameserver %s", ns) == 1) {
            cJSON *dns = cJSON_CreateString(ns);
            cJSON_AddItemToArray(dns_servers, dns);
        }
    }
    fclose(fp);
    return dns_servers;
}

char *get_os_info() {
    FILE *fp = fopen(osversion_conf_path, "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    char *os_info = NULL;
    char line[256];

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
            os_info = strdup(line + 13);
            os_info[strcspn(os_info, "\"\n")] = '\0';
            break;
        }
    }
    fclose(fp);
    return os_info;
}

char *get_kernel_version() {
    struct utsname uts;
    if (uname(&uts) == -1) {
        perror("uname");
        return NULL;
    }
    return strdup(uts.release);
}

cJSON *get_ip_addresses() {
    cJSON *ip_info = cJSON_CreateObject();
    if (ip_info == NULL) return NULL;

    struct ifaddrs *ifaddr, *ifa;
    char ip[INET6_ADDRSTRLEN];
    char gateway[512]={0};


    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, "lo") == 0 || ifa->ifa_addr == NULL) continue;

        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            if (getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) == 0) {
                int promisc_mode = check_promiscuous_mode(ifa->ifa_name);
                (family == AF_INET) ? get_v4_default_gateway(ifa->ifa_name,gateway) : get_v6_default_gateway(ifa->ifa_name,gateway);
                cJSON *ip_entry = cJSON_CreateObject();

                cJSON_AddStringToObject(ip_entry, "address", ip);
                cJSON_AddStringToObject(ip_entry, "type", (family == AF_INET) ? "IPv4" : "IPv6");
                cJSON_AddBoolToObject(ip_entry, "promiscuous_mode", promisc_mode);
                cJSON_AddStringToObject(ip_entry, "gateway", gateway);

                // 将 IP 地址放在对应的网卡名下
                cJSON *iface_entry = cJSON_GetObjectItem(ip_info, ifa->ifa_name);
                if (iface_entry == NULL) {
                    iface_entry = cJSON_CreateArray();
                    cJSON_AddItemToObject(ip_info, ifa->ifa_name, iface_entry);
                }
                cJSON_AddItemToArray(iface_entry, ip_entry);
            }
        }
    }

    freeifaddrs(ifaddr);
    return ip_info;
}

char *get_hostname_ip_json() {
    cJSON *result = cJSON_CreateObject();
    if (result == NULL) return NULL;

    // 获取主机名
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        perror("gethostname");
        strcpy(hostname, "nonehostname");
    }
    cJSON_AddStringToObject(result, "hostname", hostname);

    // 获取 IP 地址
    cJSON *ip_info = get_ip_addresses();
    if (ip_info != NULL) {
        cJSON_AddItemToObject(result, "ip_info", ip_info);
    }

    // 获取默认网关
    // cJSON *gateways = get_default_gateways();
    // if (gateways != NULL) {
    //     cJSON_AddItemToObject(result, "gateways", gateways);
    // }

    // 获取 DNS 服务器
    cJSON *dns_servers = get_dns_servers();
    if (dns_servers != NULL) {
        cJSON_AddItemToObject(result, "dns_servers", dns_servers);
    }

    // 获取操作系统信息
    char *os_info = get_os_info();
    if (os_info != NULL) {
        cJSON_AddStringToObject(result, "os_info", os_info);
        free(os_info);
    }

    // 获取内核版本信息
    char *kernel_version = get_kernel_version();
    if (kernel_version != NULL) {
        cJSON_AddStringToObject(result, "kernel_version", kernel_version);
        free(kernel_version);
    }

    // 获取系统 UUID
    char *uuid = get_host_uuid();
    if (uuid != NULL) {
        cJSON_AddStringToObject(result, "UUID", uuid);
        free(uuid);
    }

    char *json_string = cJSON_PrintUnformatted(result);
    cJSON_Delete(result);
    return json_string;
}

// Uncomment the main function for testing
/*
int main() {
    char *json_string = get_hostname_ip_json();
    if (strlen(json_string) > 2) {
        printf("%s\n", json_string);
    } else {
        printf("Failed to get hostname and IP addresses\n");
    }
    free(json_string);
    return 0;
}

*/