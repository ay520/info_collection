#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/md5.h>

#define MACHINE_ID_PATH "/etc/machine-id"

char *get_mac_address_hash(const char *interface) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return NULL;
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        return NULL;
    }
    close(fd);
    unsigned char mac[6];
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(mac, sizeof(mac), hash);
    char *hash_str = (char *)malloc(MD5_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(hash_str + i * 2, "%02x", hash[i]);
    }
    hash_str[MD5_DIGEST_LENGTH * 2] = '\0';
    return hash_str;
}

char *get_machine_id() {
    FILE *fp = fopen(MACHINE_ID_PATH, "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }
    char *machine_id = (char *)malloc(33);
    if (fgets(machine_id, 33, fp) == NULL) {
        perror("fgets error");
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    machine_id[32] = '\0';
    return machine_id;
}



char * get_host_uuid() {
    char *uuid = get_machine_id();
    if (uuid == NULL) {
        fprintf(stderr, "Failed to read /etc/machine-id, falling back to MAC address hash\n");
        uuid = get_mac_address_hash("eth0");
        if (uuid == NULL) {
            fprintf(stderr, "Error getting MAC address hash\n");
            return NULL;
        }
    }
    return uuid;
}

/*
int main()
{

    char *uuid=get_host_uuid();
    if(uuid==NULL)
    {
        fprintf(stderr, "Failed to get host uuid info,please check your runtime privillege\n");
        return 0;
    }
    
    printf("UUID: %s\n", uuid);
    free(uuid);
    return 0;

}*/