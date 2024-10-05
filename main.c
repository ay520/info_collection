#include <stdio.h>
#include "gethostinfo.c"
#include "cron_conf.c"
#include "connection.c"
#include "process_info.c"
#include "rpm_query.c"
#include "syslog.c"
#include "args_parse.c"


int main(int argc, char *argv[]) {


    ArgsConfig config = parse_arguments(argc, argv); // 获取解析结果
    // printf("sysinfo:%s,crontab:%s,netstat:%s,process:%s,rpm:%s\n",config.sysinfo,config.crontab,config.netstat,config.process,config.rpm);

    if (argc == 1) { // If no arguments are given
        printf("Usage: %s [options]\n",argv[0]);
        return -1;
    }

    char hostname[256]={0};
    
    if(config.crontab!=NULL || config.netstat!=NULL || config.process!=NULL || config.rpm!=NULL || config.sysinfo!=NULL){
       
        if (gethostname(hostname, sizeof(hostname)) == -1) {
            perror("gethostname");
            strcpy(hostname, "nonehostname");
            hostname[strlen("nonehostname")+1]='\0';
        }
        // printf("main running\n");
    }else
    {
        return -1;
    }


   if(config.sysinfo){

        printf("[*]Start to get hostinfo\n");
        char *hostinfos = get_hostname_ip_json();
        if (hostinfos!=NULL) {
            // printf("%s\n", hostinfos);
            send_log_via_syslog(hostinfos, hostname, "HOSTINFO"); 
            free(hostinfos);
        } else {
            printf("Failed to get hostname and IP addresses\n");
        }
        printf("[*]Get hostinfo Success!\n");
   }


    if(config.crontab){

        printf("[*]Start to get crontab\n");
        char *all_crontabs = read_all_crontabs();
        if(all_crontabs!=NULL){
            // printf("%s\n", all_crontabs);
            send_log_via_syslog(all_crontabs, hostname, "crontabs"); 
            free(all_crontabs);
        } else {
            printf("Failed to get crontabs\n");
        }
        printf("[*]Get crontab info Success!\n");
    }

    if(config.netstat){

        printf("[*]Start to get netstat connections\n");
        char *connections=get_connections_result();
        if(connections!=NULL){
            // printf("%s\n", connections);
            send_log_via_syslog(connections, hostname, "connections"); 
            free(connections);
        }else {
            printf("Failed to get connections\n");
        }
        printf("[*]Get netstat connections Success!\n");
    }

    if(config.process){

        printf("[*]Start to get process info\n");
        char *processinfos = get_process_info_json();
        if (processinfos) {
            // printf("%s\n", processinfos);
            send_log_via_syslog(processinfos, hostname, "processinfos"); 
            free(processinfos);
        } else {
            fprintf(stderr, "Failed to get process information\n");
        }
        printf("[*]Get process info Success!\n");
    }

    if(config.rpm){

        printf("[*]Start to get rpm info\n");
        char *rpm_info=get_rpm_infos();
        if(rpm_info){
            // printf("%s\n",rpm_info);
            send_log_via_syslog(rpm_info, hostname, "rpm_info"); 
            free(rpm_info);
        } else {
            fprintf(stderr, "Failed to get rpm_info\n");
        }
         printf("[*]Get rpm info Success!\n");
    }

    cleanup(&config); // 清理动态分配的内存
    return 0;
}