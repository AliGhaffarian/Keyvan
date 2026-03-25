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
#include <k1/logger.h>
#include <k1_map_pairs.h>
#include <string.h>

#include "opt.h"

struct args_struct args = {
    .config_filename = "",
    .loglevel = LOG_INFO,
};

char *usage_help = "usage: k1cli -c[onfig-file] -l[og-level] CONFIG_FILE";

struct option long_options[] = {
    {.name = "config-file",
     .has_arg = required_argument,
     .flag = NULL,
     .val = 'c'},
    {.name = "log-level",
     .has_arg = required_argument,
     .flag = NULL,
     .val = 'l'},
};

void print_help_and_quit()
{
    printf("%s\n", usage_help);

    printf("log levels:\n");
    for(int i = 1; i < LOG_DEBUG + 1; i++)
        printf("%s, ", LOG_LEVELS2STR[i]);
    puts("");

    exit(1);
}

void handle_args(int argc, char **argv)
{
    int required_args = 1;
    int option_index = -1;
    int err;
    int c;
    while(1) {
        c = getopt_long(argc, argv, "hc:l:", long_options, &option_index);
        if(c == -1)
            break;
        switch(c) {
        case 'c':
            args.config_filename = strdup(optarg);
            required_args--;
            break;
        case 'l':
            args.loglevel = enum_from_string_log_levels(optarg);
            if(!args.loglevel)
                print_help_and_quit();
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
