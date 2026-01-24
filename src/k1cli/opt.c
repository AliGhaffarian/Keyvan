#include <bpf/libbpf.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <verdict_record.h>
#include <inttypes.h>

#include <auth_record.h>
#include <bpf_progs.skel.h>
#include <enum_to_str_maps.h>
#include <k1_map_keys_values.h>
#include <helper.h>

#include "opt.h"

struct args_struct args = {
    .uid = -1,
    .credential = {0},
};

// clang-format off
char *usage_help = "usage: k1cli -u[id] UID -a[thenticate_checking_mechanism] AUTH_TYPE -p[assword] PASSWORD";

char *uid_help = "--uid: user id to apply the rule";

char *credential_help = "--password: password to use as credential, must be no longer than " STR(K1_BPF_STRING_MAXSIZE) " characters";

char *usb_help = STR(K1_AUTH_TYPE_USB) ":\n\
description: authenticate the user when the expected usb device is connected\n\
credential: usb device serial";

char *execve_help = STR(K1_AUTH_TYPE_EXECVE) ":\n\
description: authenticate the user when the expected file is tried to be executed (can be non-existing)\n\
credential: pathname of file";
// clang-format off


struct option long_options[] = {
    {
        .name = "uid",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'u'
    },
    {
        .name = "authenticate_checking_mechanism",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'a'
    },
    {
        .name = "credential",
        .has_arg = required_argument,
        .flag = NULL,
        .val = 'p'
    }
};

static void print_supported_auth_check_type(){
    printf("AUTH_TYPE: ");
    for (int i = 1; i < _K1_AUTH_ENUM_SIZE; i++)
        printf("%s,", enum_to_string_k1_auth_type[i]);
    puts("");
}

const static int const_k1_auth_type_usb = K1_AUTH_TYPE_USB;

void print_help_and_quit(){
    printf("%s\n", usage_help);
    puts("\n");
    printf("%s\n", uid_help);
    printf("%s\n", credential_help);
    puts("");
    print_supported_auth_check_type();
    puts("");
    printf("%s\n", usb_help);
    printf("%s\n", execve_help);
    puts("");
    exit(1);
}

int parse_auth_type(char *action){
    for(int i = 1; i < _K1_AUTH_ENUM_SIZE; i++){
        if(strcmp(action, enum_to_string_k1_auth_type[i]))
            continue;

        args.auth_cred.auth_type = i;
        return 0;
    }
    return 1;
}

void handle_args(int argc, char **argv){
    int required_args = 3;
    int option_index = -1;
    int err;
    int c;
    while(1){
        c = getopt_long(argc, argv, "u:a:p:h", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 'u':
                if(args.uid != -1)
                    break;

                char *strtol_endptr = NULL;
                long tmp_long;
                args.uid = strtoimax(optarg, &strtol_endptr, 0);
                if((int)args.uid < 0 || optarg == strtol_endptr)
                    goto arg_fail;

                required_args--;

                break;
            case 'a':
                if (args.auth_cred.auth_type != _K1_AUTH_UNSPEC)
                    break;
                err = parse_auth_type(optarg);
                if(err)
                    goto arg_fail;
                required_args--;
                break;
            case 'p':
                if(strlen(args.credential))
                    break;
                if(strlen(optarg) > K1_BPF_STRING_MAXSIZE)
                    goto arg_fail;

                strcpy(args.credential, optarg);
                required_args--;

                break;
            case 'h':
                print_help_and_quit();
                break;
            default:
                break;
        }
    }
    if(required_args){
        printf("unmet required args: %d\n", required_args);
        print_help_and_quit();
    }
    args.verdict = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC;
    return;
arg_fail:
    printf("invalid usage of -%c\n", c);
    print_help_and_quit();
}

void init_auth_cred_execve(struct bpf_progs *skel, char *credential){
    struct k1_sys_record record = {
        .is_authenticated = 0,
        .verdict_hook = args.verdict,
    };
    strcpy(record.auth_cred_execve.pathname, credential);

    struct k1_sys_auth_map_key key = {
        .uid = args.uid,
        .auth_type = K1_AUTH_TYPE_EXECVE,
    };

    int err = bpf_map__update_elem(
            skel->maps.sys_auth_map_hash,
            &key,
            sizeof(key),
            &record,
            sizeof(record),
            0
            );
}

void init_auth_cred_usb(struct bpf_progs *skel, char *credential){

    struct k1_record record = {
        .auth_cred.auth_type = K1_AUTH_TYPE_USB,
        .is_authenticated = 0,
        .uid = args.uid,
        .verdict_hook = args.verdict
    };
    strcpy(record.auth_cred.auth_cred_usb.serial, credential);

    struct k1_record_list record_list= {
        .len = 1,
        .records = {record}
    };

    int err  = bpf_map__update_elem(
            skel->maps.auth_map_hash,
            &const_k1_auth_type_usb,
            sizeof(const_k1_auth_type_usb),
            &record_list,
            sizeof(record_list),
            0
            );

}

void init_verdict(struct bpf_progs *skel){
    int err;
    struct k1_verdict_record verdict_record = {
        .is_authenticated = 0,
    };

    struct k1_verdict_map_key key = {
        .uid = args.uid,
        .hook_type = args.verdict,
    };
    err = bpf_map__update_elem(
            skel->maps.verdict_map_hash,
            &key,
            sizeof(key),
            &verdict_record,
            sizeof(verdict_record),
            0
            );
}

void init_maps_based_on_args(struct bpf_progs *skel){
    switch (args.auth_cred.auth_type) {
        case K1_AUTH_TYPE_EXECVE:
            init_auth_cred_execve(skel, args.credential);
            break;
        case K1_AUTH_TYPE_USB:
            init_auth_cred_usb(skel, args.credential);
            break; 
        default:
            print_help_and_quit();
    }
    init_verdict(skel);
    return;
}
