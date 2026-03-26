#ifndef K1_OPT
#define K1_OPT

#include <auth_record.h>
#include <bpf/libbpf.h>
#include <bpf_progs.skel.h>
#include <getopt.h>
#include <k1_limits.h>
#include <stdbool.h>
#include <unistd.h>
#include <verdict_record.h>

extern char *usage_help;

/**
 * @brief Stores parsed command line arguments.
 */
struct args_struct {
    char *config_filename;
    int loglevel;
};

extern struct args_struct args;

extern struct option long_options[];

void print_help_and_quit();

void handle_args(int argc, char **argv);

#endif
