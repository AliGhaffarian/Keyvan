#include <bpf/libbpf.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <verdict_record.h>

#include <auth_record.h>
#include <bpf_progs.skel.h>
#include <enum_to_str_maps.h>
#include <helper.h>
#include <k1_map_pairs.h>
#include <string.h>

#include "opt.h"

struct args_struct args = {
    .config_filename = "",
};

char *usage_help = "usage: k1cli -c[onfig-file] CONFIG_FILE";

struct option long_options[] = {
    {.name = "config-file",
     .has_arg = required_argument,
     .flag = NULL,
     .val = 'c'},
};

void print_help_and_quit() {
    printf("%s\n", usage_help);
    exit(1);
}

void handle_args(int argc, char **argv) {
    int required_args = 1;
    int option_index = -1;
    int err;
    int c;
    while(1) {
        c = getopt_long(argc, argv, "hc:", long_options, &option_index);
        if(c == -1)
            break;
        switch(c) {
        case 'c':
            args.config_filename = strdup(optarg);
            required_args--;
            break;
        case 'h':
            print_help_and_quit();
            break;
        default:
            break;
        }
    }
    if(required_args) {
        printf("unmet required args: %d\n", required_args);
        print_help_and_quit();
    }
    return;
}

void register_user(struct bpf_progs *skel, uid_t uid) {
    bpf_map__update_elem(
        skel->maps.registered_uids_map_hash,
        &uid,
        sizeof(struct k1_users_having_sid_verdict_map_key),
        &uid,
        sizeof(DUMMY_MAP_VALUE_T),
        BPF_ANY);
}

int register_user_wanting_sid_verdict(struct bpf_progs *skel, uid_t uid) {
    return bpf_map__update_elem(
        skel->maps.users_having_sid_verdict_map_hash,
        &uid,
        sizeof(struct k1_users_having_sid_verdict_map_key),
        &uid,
        sizeof(DUMMY_MAP_VALUE_T),
        BPF_ANY);
}
