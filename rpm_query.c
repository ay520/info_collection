#include <stdio.h>
#include <stdlib.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmts.h>
#include "include/cJSON.h"

void print_package_info(const char *name, const char *version, const char *release, const char *arch,const char *License,const char *Group,const char *Vendor,const char *Packager,const char *URL,const char *Source_RPM) {
     
    if (name && version && release && arch) {
        printf("Name: %s, Version: %s, Release: %s, Architecture: %s,License: %s,Group: %s, Vendor: %s, Packager: %s, URL: %s, Source_RPM: %s\n",
         name,version,release,arch,License,Group,Vendor,Packager,URL,Source_RPM);
    } else {
        fprintf(stderr, "Warning: One or more package details are missing.\n");
    }
}

char * print_rpm_info(rpmts ts) {
    rpmdbMatchIterator mi = rpmtsInitIterator(ts, RPMTAG_NAME, NULL, 0);
    Header h;
    cJSON *json_array = cJSON_CreateArray();
    while ((h = rpmdbNextIterator(mi)) != NULL) {
        const char *name = NULL, *version = NULL, *release = NULL, *arch = NULL,*Group=NULL,*Vendor=NULL,*Source_RPM=NULL;
        // const char *Packager=NULL, *URL=NULL,*License=NULL;
        // const char *Description=NULL,*Summary=NULL;
        cJSON *json_item = cJSON_CreateObject();
        // 使用 headerGetString 获取信息
        name = headerGetString(h, RPMTAG_NAME);
        version = headerGetString(h, RPMTAG_VERSION);
        release = headerGetString(h, RPMTAG_RELEASE);
        arch = headerGetString(h, RPMTAG_ARCH);
        // Summary= headerGetString(h, RPMTAG_SUMMARY);
        // License= headerGetString(h, RPMTAG_LICENSE);
        Group= headerGetString(h, RPMTAG_GROUP);
        Vendor= headerGetString(h, RPMTAG_VENDOR);
        // Packager= headerGetString(h, RPMTAG_PACKAGER);
        // URL= headerGetString(h, RPMTAG_URL);
        Source_RPM= headerGetString(h, RPMTAG_SOURCERPM);
        // Description= headerGetString(h, RPMTAG_DESCRIPTION);
        cJSON_AddStringToObject(json_item, "name", name); 
        cJSON_AddStringToObject(json_item, "version", version); 
        cJSON_AddStringToObject(json_item, "release", release); 
        cJSON_AddStringToObject(json_item, "arch", arch); 
        // cJSON_AddStringToObject(json_item, "License", License); 
        cJSON_AddStringToObject(json_item, "Group", Group); 
        cJSON_AddStringToObject(json_item, "Vendor", Vendor); 
        // cJSON_AddStringToObject(json_item, "Packager", Packager); 
        // cJSON_AddStringToObject(json_item, "URL", URL); 
        cJSON_AddStringToObject(json_item, "Source_RPM", Source_RPM); 
        // print_package_info(name, version, release, arch,License,Group,Vendor,Packager,URL,Source_RPM);
        cJSON_AddItemToArray(json_array, json_item);
    }
    rpmdbFreeIterator(mi);

    char *json_output = cJSON_PrintUnformatted(json_array);
    cJSON_Delete(json_array);
    return json_output;
}


char * get_rpm_infos(){

    if (rpmReadConfigFiles(NULL, NULL) != 0) {
        fprintf(stderr, "Error: Failed to read RPM configuration files.\n");
        return NULL;
    }

    rpmts ts = rpmtsCreate();
    if (!ts) {
        fprintf(stderr, "Error: Failed to create RPM transaction set.\n");
        return NULL;
    }

    char *rpm_list=print_rpm_info(ts);
    rpmtsFree(ts);
    // printf("%s\n",rpm_list);
    // free(rpm_list);
    return rpm_list;

}

/*
int main() {
    if (rpmReadConfigFiles(NULL, NULL) != 0) {
        fprintf(stderr, "Error: Failed to read RPM configuration files.\n");
        return EXIT_FAILURE;
    }

    rpmts ts = rpmtsCreate();
    if (!ts) {
        fprintf(stderr, "Error: Failed to create RPM transaction set.\n");
        return EXIT_FAILURE;
    }

    char *rpm_list=print_rpm_info(ts);
    rpmtsFree(ts);
    printf("%s\n",rpm_list);
    free(rpm_list);

    return EXIT_SUCCESS;
}
*/