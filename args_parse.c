#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // For getopt and optarg
#include <getopt.h>
#include <string.h>

typedef struct {
    int verbose;
    char *sysinfo;
    char *process; // 仍然需要使用输出文件
    char *netstat;
    char *rpm;
    char *crontab;
} ArgsConfig;


void cleanup(ArgsConfig *config) {
    if(config->sysinfo!=NULL){
        // printf("free sysinfo ok\n");
        free(config->sysinfo); // 释放动态分配的内存
        config->sysinfo = NULL; // 避免悬挂指针
    }
    if(config->process!=NULL){
        // printf("free process\n");
        free(config->process);
        config->process = NULL;
    }
    if(config->netstat!=NULL){
        // printf("free netstat\n");
        free(config->netstat);
        config->netstat = NULL;
    }
    if(config->rpm!=NULL){
        // printf("free rpm\n");
        free(config->rpm);
        config->rpm = NULL;
    }
    if(config->crontab!=NULL){
        // printf("free crontab\n");
        free(config->crontab);
        config->crontab = NULL;
    }
}

ArgsConfig parse_arguments(int argc, char *argv[]) {
    int c;
    int option_index = 0;
    ArgsConfig config = {0};
    // Short options: a:b:c
    static struct option long_options[] =
        {{"verbose", no_argument, NULL, 'v'},
         {"sysinfo", required_argument, NULL, 's'},
         {"process", required_argument, NULL, 'p'},
         {"netstat", required_argument, NULL, 'n'},
         {"rpm",     required_argument, NULL, 'r'},
         {"crontab", required_argument, NULL, 'c'},
         {"help",    no_argument, NULL, 'h'},
        //  {"other", required_argument, NULL, 'o'},
         {NULL, 0, NULL, 0}
        };
    
    while ((c = getopt_long(argc, argv, "vhs:p:n:r:c:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'v':
                config.verbose = 1;
                printf("version:1.1\n");
                break;
            case 's':
                config.sysinfo = strdup(optarg); 
                // printf("sysinfo: %s\n", optarg);
                break;
            case 'p':
                config.process= strdup(optarg); 
                break;
            case 'n':
                config.netstat = strdup(optarg);
                break;        
            case 'r':
                config.rpm = strdup(optarg);
                break;  
            case 'c':
                config.crontab = strdup(optarg); 
                break;                  
            case 'h':  /* '?' */
                printf("Usage: program [options]\n"
                       "Options:\n"
                       "-v, --verbose          Show Current Version\n"
                       "-s, --sysinfo [y/no]   Get system  Info\n"
                       "-p, --process [y/no]   Get process Info\n"
                       "-n, --netstat [y/no]   Get netstat Info\n"
                       "-r, --rpm     [y/no]   Get rpm     Info\n"
                       "-c, --crontab [y/no]   Get crontab Info\n"
                       );
                exit(0);
        }
    }

    
    return config;  // 返回配置信息
}

/*
int main(int argc, char *argv[]) {
    // Initialize getopt_long with long options as well.
    ArgsConfig config = parse_arguments(argc, argv); // 获取解析结果

    if (argc == 1) { // If no arguments are given
        printf("Usage: %s [options]\n",argv[0]);
        return -1;
    }

    printf("main config.inputfile:%s\n",config.input_file);
    printf("main config.outfile:%s\n",config.output_file);
    printf("main config.verbose:%d\n",config.verbose);

    cleanup(&config); // 清理动态分配的内存
    
    // More logic here based on the parsed options

    return 0; // Successful termination
}*/