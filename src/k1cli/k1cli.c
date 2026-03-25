#include <bpf/libbpf.h>
#include <getopt.h>
#include <k1/linked_list.h>
#include <k1_map_pairs.h>
#include <stdbool.h>
#include <unistd.h>
#include <verdict_record.h>

#include <auth_record.h>
#include <bpf_progs.skel.h>
#include <k1/exception/pathname.h>
#include <k1/logger.h>
#include <parser_structs.h>

#include "config_ops.h"
#include "opt.h"

int yyparse();
extern FILE *yyin;
extern struct k1_node *ruleset_linked_list;

int main(int argc, char **argv)
{
    FILE *config_file = NULL;
    int err = 0;
    struct bpf_progs *skel = NULL;

    handle_args(argc, argv);
    current_log_level = args.loglevel;

    config_file = fopen(args.config_filename, "r");

    yyin = config_file;
    yyparse();

    skel = bpf_progs__open_and_load();
    if(!skel) {
        printf("%s\n", strerror(errno));
        return 1;
    }

    complete_ruleset_linked_list(ruleset_linked_list);
    if(current_log_level == LOG_DEBUG)
        dump_ruleset_linked_list(ruleset_linked_list);
    err = register_ruleset_linked_list(skel, ruleset_linked_list);
    if(err)
        return err;

    bpf_progs__attach(skel);
    while(1) {
    }
}
