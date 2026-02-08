#include <bpf/libbpf.h>
#include <getopt.h>
#include <k1/linked_list.h>
#include <k1_map_pairs.h>
#include <stdbool.h>
#include <unistd.h>
#include <verdict_record.h>

#include <auth_record.h>
#include <bpf_progs.skel.h>

#include "opt.h"

extern struct k1_node *head_auth_map_pair;
extern struct k1_node *head_verdict_map_user_pair;

int yyparse();

int register_auth_pairs_to_map(struct bpf_progs *skel, struct k1_node *head)
{
    int err = 0;

    struct k1_node *current_auth = head;
    while(current_auth) {
        struct k1_auth_map_pair *current_auth_pair = current_auth->data;
        err = bpf_map__update_elem(
            skel->maps.auth_map_hash,
            &current_auth_pair->key,
            sizeof(current_auth_pair->key),
            &current_auth_pair->value,
            sizeof(current_auth_pair->value),
            0);
        if(err) {
            printf("%s\n", strerror(errno));
            goto finish;
        }
        if(current_auth_pair->value.verdict_entry_lookup_info
               .verdict_map_type == K1_VERDICT_MAP_SID)
            register_user_wanting_sid_verdict(skel, current_auth_pair->key.uid);
        current_auth = current_auth->next;
    }
finish:
    return err;
}

int register_verdict_pairs_to_map(struct bpf_progs *skel, struct k1_node *head)
{
    int err = 0;

    struct k1_node *current_verdict = head;
    while(current_verdict) {
        struct k1_verdict_map_user_pair *current_verdict_pair =
            current_verdict->data;
        err = bpf_map__update_elem(
            skel->maps.verdict_map_user_hash,
            &current_verdict_pair->key,
            sizeof(current_verdict_pair->key),
            &current_verdict_pair->value,
            sizeof(current_verdict_pair->value),
            0);
        if(err) {
            printf("%s\n", strerror(errno));
            goto finish;
        }
        register_user(skel, current_verdict_pair->key.uid);
        current_verdict = current_verdict->next;
    }
finish:
    return err;
}

int main(int argc, char **argv)
{
    FILE *stdin_bak = stdin;
    FILE *config_file = NULL;
    int err = 0;
    struct bpf_progs *skel = NULL;

    handle_args(argc, argv);

    skel = bpf_progs__open_and_load();
    if(!skel) {
        printf("%s\n", strerror(errno));
        return 1;
    }

    config_file = fopen(args.config_filename, "r");

    stdin = config_file;
    yyparse();
    stdin = stdin_bak;

    err = register_auth_pairs_to_map(skel, head_auth_map_pair);
    if(err)
        return err;
    err = register_verdict_pairs_to_map(skel, head_verdict_map_user_pair);
    if(err)
        return err;

    bpf_progs__attach(skel);
    while(1) {
    }
}
