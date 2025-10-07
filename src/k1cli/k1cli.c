#include <bpf/libbpf.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include <auth_list.h>
#include <bpf_progs.skel.h>

#define _STR(x) #x
#define STR(x) _STR(x)


char *usage_help = "usage: k1cli -u[id] UID -p[assword] PASSWORD";

uid_t uid = -1;
char *uid_help = "--uid: user id to apply the rule";

char password[K1_BPF_STRING_MAXSIZE] = {0};
char *password_help = "--password: password to use as credential, must be no longer than " STR(K1_BPF_STRING_MAXSIZE) " characters";

struct option long_options[] = {
    {
        .name = "uid",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'u'
    },
    {
        .name = "password",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'p'
    }
};

void print_help_and_quit(){
    printf("%s\n", usage_help);
    printf("%s\n", uid_help);
    printf("%s\n", password_help);
    exit(1);
}

void handle_args(int argc, char **argv){
    int required_args = 2;
    int option_index = -1;
    while(1){
        int c = getopt_long(argc, argv, "u:p:h", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 'u':
                if(uid == -1)
                    required_args--;
                uid = atoi(optarg);
                if(uid < 0)
                    goto arg_fail;
                break;
                
            case 'p':
                if(*password == 0)
                    required_args--;
                if(strlen(optarg) > K1_BPF_STRING_MAXSIZE)
                    goto arg_fail;
                strcpy(password, optarg);
                break;
            default:
            case 'h':
                print_help_and_quit();
                break;
        }
    }
    if(required_args){
        printf("unmet required args: %d\n", required_args);
        print_help_and_quit();
    }
    return;
arg_fail:
    printf("invalid usage of %s\n", long_options[option_index].name);
    print_help_and_quit();
}

int main(int argc, char **argv){
    handle_args(argc, argv);

    struct bpf_progs *skel;
    struct k1_record record = {
        .is_authenticated = 0,
        .verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC,
    };
    record.auth_check_detail.auth_type = K1_AUTH_TYPE_EXECVE;
    strcpy(record.auth_check_detail.auth_execve.pathname, password);
    
    struct k1_record_list record_list= {
        .len = 1,
        .records = {record}
    };

    skel = bpf_progs__open_and_load();

    int err  = bpf_map__update_elem(
            skel->maps.auth_map_hash_sys, 
            &uid, 
            sizeof(uid),
            &record_list,
            sizeof(record_list),
            0
            );
    if(err){
        printf("%s\n", strerror(errno));
        bpf_progs__destroy(skel);
        return 1;
    }

    if(!skel){
        printf("%s\n", strerror(errno));
        return 1;
    }
    bpf_progs__attach(skel);
    while(1){

    }
}
