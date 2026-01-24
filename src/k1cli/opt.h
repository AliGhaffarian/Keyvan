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

extern uid_t uid;
extern char *uid_help;

extern char credential[K1_BPF_STRING_MAXSIZE];
extern char *credential_help;

extern char *usb_help;
extern char *execve_help;

struct args_struct {
    uid_t uid;
    enum K1_VERDICT_HOOK verdict;
    struct k1_auth_cred auth_cred;
    char credential[K1_BPF_STRING_MAXSIZE];
};

extern struct option long_options[];

void print_help_and_quit();

int parse_auth_type(char *action);

void handle_args(int argc, char **argv);

void init_auth_cred_execve(struct bpf_progs *skel, char *credential);

void init_auth_cred_usb(struct bpf_progs *skel, char *credential);

void init_maps_based_on_args(struct bpf_progs *skel);

#endif
