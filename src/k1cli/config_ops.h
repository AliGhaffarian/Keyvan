#pragma once

#include <bpf_progs.skel.h>
#include <parser_structs.h>

/*
 * @file config_ops contains all operations regarding the parsed configurations
 * these operations include registration and dumping to stdout.
 */

void dump_ruleset(struct k1_policies_head_node *policies_head_node);
void dump_ruleset_linked_list(struct k1_node *policies_head_linked_list);
void dump_exception_linked_list(struct k1_node *exception_linked_list);
int register_ruleset(
    struct bpf_progs *skel, struct k1_policies_head_node *policies_head_node);
int register_ruleset_linked_list(
    struct bpf_progs *skel, struct k1_node *policies_head_linked_list);
int complete_ruleset(struct k1_policies_head_node *policies_head_node);
int complete_ruleset_linked_list(struct k1_node *policies_head_linked_list);

int register_user(struct bpf_progs *skel, uid_t euid);
int register_user_wanting_sid_verdict(struct bpf_progs *skel, uid_t euid);
int register_auth_pair_to_map(
    struct bpf_progs *skel, struct k1_auth_map_pair *auth_map_pair);
int register_verdict_pair_to_map(
    struct bpf_progs *skel,
    struct k1_verdict_map_user_pair *verdict_map_user_pair);
int register_exceptions_pathname(
    struct bpf_progs *skel,
    struct k1_node *head,
    uid_t euid,
    enum K1_VERDICT_HOOK verdict_hook,
    enum K1_VERDICT_MAP_TYPE verdict_map_type);
