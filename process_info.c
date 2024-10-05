#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "include/cJSON.h"

#define PATH_MAX 4096
#define STAT_BUFFER_SIZE 4096
#define CMDLINE_BUFFER_SIZE 4096
#define FD_BUFFER_SIZE 256
#define TIME_BUFFER_SIZE 64

int read_file(const char *filename, unsigned char **data);
char *get_process_info_json();
int get_file_descriptor_info(int pid, int fd, char *buf, size_t buf_size);
int get_process_stat_info(int pid, int *ppid, char *state, char *comm);
int get_process_file_info(const char *path, char *start_time, uid_t *uid, gid_t *gid, const char *exe_path, char *create_time, long *file_size);
int get_process_file_md5(const char *filename, char md5_str[33]);
int get_process_cmdline_info(int pid, char *cmdline, size_t cmdline_size, char *comm);

/*
int main() {
    char *json_output = get_process_info_json();
    if (json_output) {
        printf("%s\n", json_output);
        free(json_output);
    } else {
        fprintf(stderr, "Failed to get process information\n");
    }
    return 0;
}
*/

int read_file(const char *filename, unsigned char **data) {
    if (!filename || !data) return -1;

    FILE *file = fopen(filename, "rb");
    if (!file) return -1;

    fseek(file, 0, SEEK_END);
    off_t length = ftell(file);
    fseek(file, 0, SEEK_SET);

    *data = malloc(length);
    if (!*data) {
        fclose(file);
        return -1;
    }

    size_t read_length = fread(*data, 1, length, file);
    fclose(file);

    if (length<0 || read_length != (size_t)length) {
        free(*data);
        return -1;
    }

    return length;
}

int get_file_descriptor_info(int pid, int fd, char *buf, size_t buf_size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    ssize_t link_length = readlink(path, buf, buf_size - 1);
    if (link_length == -1) return -1;
    buf[link_length] = '\0';
    return 0;
}

int get_process_stat_info(int pid, int *ppid, char *state, char *comm) {
    char stat_file[PATH_MAX];
    snprintf(stat_file, sizeof(stat_file), "/proc/%d/stat", pid);
    char stat_info[STAT_BUFFER_SIZE] = {0};

    int stat_fd = open(stat_file, O_RDONLY);
    if (stat_fd < 0) return -1;

    ssize_t read_length = read(stat_fd, stat_info, sizeof(stat_info) - 1);
    close(stat_fd);
    if (read_length <= 0) return -1;

    sscanf(stat_info, "%*d %s %c %d", comm, state, ppid);
    return 0;
}

int get_process_file_info(const char *path, char *start_time, uid_t *uid, gid_t *gid, const char *exe_path, char *create_time, long *file_size) {
    struct stat st;
    if (stat(path, &st) != 0) {
        // 内核进程可能没有文件路径信息，所以我们返回默认值
        snprintf(start_time, TIME_BUFFER_SIZE, "N/A");
        *uid = -1;
        *gid = -1;
        return 0;  // 返回0表示未出错但没有文件信息
    }

    strftime(start_time, TIME_BUFFER_SIZE, "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
    *uid = st.st_uid;
    *gid = st.st_gid;

    if (stat(exe_path, &st) != 0) {
        snprintf(create_time, TIME_BUFFER_SIZE, "N/A");
        *file_size = 0;
        return 0;  // 返回0表示未出错但没有文件信息
    }

    strftime(create_time, TIME_BUFFER_SIZE, "%Y-%m-%d %H:%M:%S", localtime(&st.st_ctime));
    *file_size = st.st_size;
    return 0;
}

int get_process_file_md5(const char *filename, char md5_str[33]) {
    if (!filename || !md5_str) return -1;

    unsigned char *data = NULL;
    int length = read_file(filename, &data);
    if (length <= 0) {
        if (data) free(data);
        strcpy(md5_str, length == 0 ? "empty" : "0");
        return -1;
    }

    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    MD5(data, length, md5_hash);
    free(data);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(md5_str + i * 2, "%02x", md5_hash[i]);
    }
    return 0;
}

int get_process_cmdline_info(int pid, char *cmdline, size_t cmdline_size, char *comm) {
    char cmdline_file[PATH_MAX];
    snprintf(cmdline_file, sizeof(cmdline_file), "/proc/%d/cmdline", pid);

    int cmdline_fd = open(cmdline_file, O_RDONLY);
    if (cmdline_fd < 0) {
        perror(cmdline_file);
        return -1; // Failed to open the file
    }

    ssize_t read_length = read(cmdline_fd, cmdline, cmdline_size - 1);
    close(cmdline_fd);
    
    if (read_length < 0) {
        perror("Failed to read cmdline file");
        return -1; // Failed to read the file
    }

    if (read_length == 0) {
        strncpy(cmdline, comm, cmdline_size - 1);
        cmdline[cmdline_size - 1] = '\0'; // Ensure null termination
        return 0; // No cmdline available, returning comm
    }

    // Null-terminate the string
    cmdline[read_length] = '\0';

    // Replace null characters with spaces, but limit to at most 5 replacements
    int count = 0;
    for (ssize_t i = 0; i < read_length; ++i) {
        if (cmdline[i] == '\0') {
            if (count < 10) {
                cmdline[i] = ' ';
                count++;
            } else {
                break; // Stop replacing after 5 nulls
            }
        }
    }
    // Trim trailing space
    ssize_t last_index = strlen(cmdline) - 1;
    while (last_index >= 0 && cmdline[last_index] == ' ') {
        cmdline[last_index] = '\0'; // Set to null to truncate
        last_index--;
    }

    return 0; // Success
}


char *get_process_info_json() {
    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("Cannot open /proc");
        return NULL;
    }

    cJSON *processes = cJSON_CreateArray();
    if (!processes) {
        closedir(proc);
        perror("Cannot create cJSON array");
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        int pid;
        if (sscanf(entry->d_name, "%d", &pid) != 1) continue;

        char path[PATH_MAX], exe_file[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d", pid);
        snprintf(exe_file, sizeof(exe_file), "/proc/%d/exe", pid);

        int ppid = -1;
        char comm[256] = "";
        char state[8] = "";
        if (get_process_stat_info(pid, &ppid, state, comm) != 0) {
            // 继续处理，即使获取 stat 信息失败
            strcpy(comm, "N/A");
            strcpy(state, "N/A");
        }

        char cmdline[CMDLINE_BUFFER_SIZE] = "";
        if (get_process_cmdline_info(pid, cmdline, sizeof(cmdline), comm) != 0) {
            // 继续处理，即使获取 cmdline 信息失败
            strcpy(cmdline, "N/A");
        }

        char exe_path[PATH_MAX] = "";
        ssize_t link_length = readlink(exe_file, exe_path, sizeof(exe_path) - 1);
        if (link_length == -1) {
            strcpy(exe_path, "N/A");
        } else {
            exe_path[link_length] = '\0';  // 确保字符串以 null 结尾
        }

        char start_time[TIME_BUFFER_SIZE] = "";
        uid_t uid = -1;
        gid_t gid = -1;
        char create_time[TIME_BUFFER_SIZE] = "";
        long file_size = -1;

        if (get_process_file_info(path, start_time, &uid, &gid, exe_path, create_time, &file_size) != 0) {
            // 继续处理，即使获取文件信息失败
            strcpy(start_time, "N/A");
            strcpy(create_time, "N/A");
            uid = gid = -1;
            file_size = 0;
        }

        char md5_str[33] = "";
        if (get_process_file_md5(exe_path, md5_str) != 0) {
            // 继续处理，即使获取 MD5 信息失败
            strcpy(md5_str, "N/A");
        }

        cJSON *process = cJSON_CreateObject();
        if (!process) {
            perror("Cannot create cJSON object");
            continue;
        }

        cJSON_AddNumberToObject(process, "pid", pid);
        cJSON_AddNumberToObject(process, "ppid", ppid);
        cJSON_AddStringToObject(process, "cmdline", cmdline);
        cJSON_AddStringToObject(process, "task_state", state);
        cJSON_AddStringToObject(process, "exe_path", exe_path);
        cJSON_AddStringToObject(process, "md5", md5_str);
        cJSON_AddNumberToObject(process, "uid", uid);
        cJSON_AddNumberToObject(process, "gid", gid);
        cJSON_AddNumberToObject(process, "file_size", file_size);
        cJSON_AddStringToObject(process, "start_time", start_time);
        cJSON_AddStringToObject(process, "create_time", create_time);

        cJSON *fds = cJSON_CreateObject();
        if (fds) {
            char fd_buf[FD_BUFFER_SIZE];
            for (int fd = 0; fd <= 2; fd++) {
                if (get_file_descriptor_info(pid, fd, fd_buf, sizeof(fd_buf)) == 0) {
                    cJSON_AddStringToObject(fds, (fd == 0) ? "stdin" : (fd == 1) ? "stdout" : "stderr", fd_buf);
                } else {
                    cJSON_AddStringToObject(fds, (fd == 0) ? "stdin" : (fd == 1) ? "stdout" : "stderr", "N/A");
                }
            }
            cJSON_AddItemToObject(process, "fd", fds);
        }

        cJSON_AddItemToArray(processes, process);
    }

    closedir(proc);
    char *json_output = cJSON_PrintUnformatted(processes);
    cJSON_Delete(processes);
    return json_output;
}