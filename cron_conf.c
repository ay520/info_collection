#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "include/cJSON.h"
#include <stdbool.h>
#include <ctype.h>

char* read_crontab_file(const char* file_path);
bool is_comment_line(const char *line);
char* filter_comment_lines(const char *content);
cJSON* read_user_crontabs();
cJSON* read_cron_d_files();
cJSON* read_cron_files(const char* dir_path);
char* read_all_crontabs();

// 读取 crontab 文件
char* read_crontab_file(const char* file_path)
{
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL)
    {
        char error_file_path[512];
        snprintf(error_file_path, sizeof(error_file_path), "Error reading file: %s", file_path);
        perror(error_file_path);
        return NULL;
    }
    
    char* content = NULL;
    size_t content_len = 0;
    char buffer[1024];
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        size_t buffer_len = strlen(buffer);
        char* new_content = realloc(content, content_len + buffer_len + 1);
        if (new_content == NULL)
        {
            perror("content realloc");
            free(content);
            fclose(fp);
            return NULL;
        }
        content = new_content;
        memcpy(content + content_len, buffer, buffer_len);
        content_len += buffer_len;
        content[content_len] = '\0';
    }
    
    fclose(fp);
    return content;
}

// 检查行是否为注释行
bool is_comment_line(const char *line)
{
    for (size_t i = 0; line[i]; ++i)
    {
        if (line[i] == '#')
            return true;
        if (!isspace(line[i]))
            return false;
    }
    return false;
}

// 过滤掉注释行
char* filter_comment_lines(const char *content)
{
    const char *line = content;
    size_t len = strlen(content);
    char *filtered = malloc(len + 1);
    size_t pos = 0;
    while (line)
    {
        const char *next_line = strchr(line, '\n');
        size_t line_len = next_line ? (size_t)(next_line - line) : strlen(line);
        if (!is_comment_line(line))
        {
            strncpy(filtered + pos, line, line_len);
            pos += line_len;
            if (next_line)
                filtered[pos++] = '\n';
        }
        line = next_line ? next_line + 1 : NULL;
    }
    filtered[pos] = '\0';
    return filtered;
}

// 读取 cron 目录下的文件
cJSON* read_cron_files(const char* dir_path)
{
    DIR* dir = opendir(dir_path);
    if (dir == NULL)
    {
        char error_dir[512];
        snprintf(error_dir, sizeof(error_dir), "Error opening directory: %s", dir_path);
        perror(error_dir);
        return NULL;
    }
    
    cJSON *cron_files = cJSON_CreateArray();
    
    struct dirent *entry;
    char file_path[256];
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
        {
            continue;
        }
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
        char* content = read_crontab_file(file_path);
        if (content == NULL)
        {
            continue;  // Skip null content
        }
        
        char* filtered_content = filter_comment_lines(content);
        if (filtered_content == NULL) {
            free(content);
            continue;
        }
        
        cJSON *cron_file = cJSON_CreateObject();
        if (cron_file) {
            cJSON_AddStringToObject(cron_file, "file_path", file_path);
            cJSON_AddStringToObject(cron_file, "content", filtered_content);
            cJSON_AddItemToArray(cron_files, cron_file);
        }
        
        free(filtered_content);
        free(content);
    }
    
    closedir(dir);
    return cron_files;
}

// 读取用户 crontab 文件
cJSON* read_user_crontabs()
{
    // 支持不同的系统路径
    cJSON *user_crontabs = cJSON_CreateArray();
    
    // 检查两个常见路径
    cJSON *user_crontab_1 = read_cron_files("/var/spool/cron");
    if (user_crontab_1) {
        cJSON_AddItemToArray(user_crontabs, user_crontab_1);
    }
    
    if (access("/var/spool/cron/crontabs", F_OK) == 0) {
        cJSON *user_crontab_2 = read_cron_files("/var/spool/cron/crontabs");
        if (user_crontab_2) {
            cJSON_AddItemToArray(user_crontabs, user_crontab_2);
        }
    }
    return user_crontabs;
}

// 读取 cron.d 文件
cJSON* read_cron_d_files()
{
    return read_cron_files("/etc/cron.d");
}

// 读取所有 crontab，包括额外路径
char* read_all_crontabs()
{
    cJSON *all_crontabs = cJSON_CreateObject();
    
    // 读取系统 crontab 文件
    char* content = read_crontab_file("/etc/crontab");
    if (content != NULL)
    {
        char* filtered_content = filter_comment_lines(content);
        cJSON_AddStringToObject(all_crontabs, "/etc/crontab", filtered_content);
        free(filtered_content);
        free(content);
    }
    
    // 读取用户 crontab 文件
    cJSON *user_crontabs = read_user_crontabs();
    if (user_crontabs != NULL)
    {
        cJSON_AddItemToObject(all_crontabs, "user_crontabs", user_crontabs);
    }
    
    // 读取 cron.d 文件
    cJSON *cron_d_files = read_cron_d_files();
    if (cron_d_files != NULL)
    {
        cJSON_AddItemToObject(all_crontabs, "cron_d_files", cron_d_files);
    }

    // 读取其他 cron 路径
    const char *cron_paths[] = {
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly"
    };
    
    for (size_t i = 0; i < sizeof(cron_paths) / sizeof(cron_paths[0]); ++i) {
        cJSON *cron_files = read_cron_files(cron_paths[i]);
        if (cron_files != NULL) {
            cJSON_AddItemToObject(all_crontabs, cron_paths[i], cron_files);
        }
    }

    // 输出 JSON
    char *json_string = cJSON_PrintUnformatted(all_crontabs);
    
    // 清理
    cJSON_Delete(all_crontabs);
    return json_string;
}

// 测试函数
void test_read_crontab_file() {
    printf("Testing read_crontab_file:\n");
    char *content = read_crontab_file("/etc/crontab");
    if (content != NULL) {
        printf("Successfully read /etc/crontab:\n%s\n", content);
        free(content);
    } else {
        printf("Failed to read /etc/crontab\n");
    }
}

void test_read_cron_files() {
    printf("Testing read_cron_files:\n");
    cJSON *result = read_cron_files("/etc/cron.d");
    if (result != NULL) {
        char *json_output = cJSON_Print(result);
        printf("Successfully read /etc/cron.d:\n%s\n", json_output);
        free(json_output);
        cJSON_Delete(result);
    } else {
        printf("Failed to read /etc/cron.d\n");
    }
}
/*
int main()
{
    // 测试读取功能
    // test_read_crontab_file();
    // test_read_cron_files();

    // 如果您想要读取所有 crontabs 也可以调用以下函数
    char *all_crontabs = read_all_crontabs();
    printf("All crontabs:\n%s\n", all_crontabs);
    
    // 清理
    free(all_crontabs);
    
    return 0;
}
*/