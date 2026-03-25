#include <bpf_progs.skel.h>
#include <k1/exception/pathname.h>
#include <k1/logger.h>

#include "config_ops.h"

void dump_ruleset_linked_list(struct k1_node *policies_head_linked_list)
{
    struct k1_node *current_node = policies_head_linked_list;
    struct k1_policies_head_node *current_head = NULL;

    while(current_node) {
        current_head = (struct k1_policies_head_node *)current_node->data;
        dump_ruleset(current_head);
        current_node = current_node->next;
    }
}

void dump_ruleset(struct k1_policies_head_node *policies_head_node)
{

    struct k1_node *current_policy_node =
        policies_head_node->policies_linked_list;
    struct k1_policy *current_policy = NULL;

    printf("START OF RULESET\n");
    while(current_policy_node) {
        current_policy = (struct k1_policy *)current_policy_node->data;

        __builtin_dump_struct(policies_head_node, printf);
        __builtin_dump_struct(current_policy, printf);
        if(current_policy->auth_map_pair)
            __builtin_dump_struct(current_policy->auth_map_pair, printf);
        if(current_policy->verdict_map_user_pair)
            __builtin_dump_struct(
                current_policy->verdict_map_user_pair, printf);
        if(current_policy->exception_linked_list)
            dump_exception_linked_list(current_policy->exception_linked_list);

        current_policy_node = current_policy_node->next;
    }
    printf("END OF RULESET\n");
}

void dump_exception_linked_list(struct k1_node *exception_linked_list)
{
    struct k1_node *current_exception_node = exception_linked_list;
    struct k1_parsed_exception_pathname *current_exception;
    int counter = 0;

    while(current_exception_node) {
        current_exception =
            (struct k1_parsed_exception_pathname *)current_exception_node->data;

        printf("exception[%d]:\n", counter++);
        printf("pathname: %s\n", current_exception->pathname);
        printf("is_whitelist: %d\n", current_exception->is_whitelist);

        current_exception_node = current_exception_node->next;
    }
}

int complete_ruleset_linked_list(struct k1_node *policies_head_linked_list)
{
    int err = 0;
    struct k1_node *current_node = policies_head_linked_list;
    struct k1_policies_head_node *current_head = NULL;

    while(current_node) {
        current_head = (struct k1_policies_head_node *)current_node->data;
        err = complete_ruleset(current_head);
        if(err) {
            logger(LOG_ERROR, stdout, "error while registering ruleset\n");
            break;
        }
        current_node = current_node->next;
    }

    return err;
}

int complete_ruleset(struct k1_policies_head_node *policies_head_node)
{
    int err = 0;

    struct k1_node *current_policy_node =
        policies_head_node->policies_linked_list;
    struct k1_policy *current_policy = NULL;

    while(current_policy_node) {
        current_policy = (struct k1_policy *)current_policy_node->data;

        if(current_policy->verdict_map_user_pair) {

            current_policy->auth_map_pair->value.verdict_entry_lookup_info
                .verdict_map_type = current_policy->verdict_sub_type;
            current_policy->auth_map_pair->value.verdict_entry_lookup_info
                .verdict_hook =
                current_policy->verdict_map_user_pair->key.verdict_hook;

            current_policy->verdict_map_user_pair->key.euid =
                policies_head_node->euid;
        }

        current_policy->auth_map_pair->key.euid = policies_head_node->euid;

        current_policy_node = current_policy_node->next;
    }

    return err;
}

int register_ruleset_linked_list(
    struct bpf_progs *skel, struct k1_node *policies_head_linked_list)
{
    int err = 0;
    struct k1_node *current_node = policies_head_linked_list;
    struct k1_policies_head_node *current_head = NULL;

    while(current_node) {
        current_head = (struct k1_policies_head_node *)current_node->data;
        err = register_ruleset(skel, current_head);
        if(err) {
            logger(LOG_ERROR, stdout, "error while registering ruleset\n");
            break;
        }
        current_node = current_node->next;
    }

    return err;
}

int register_ruleset(
    struct bpf_progs *skel, struct k1_policies_head_node *policies_head_node)
{
    int err = 0;
    struct k1_node *current_policy_node =
        policies_head_node->policies_linked_list;
    struct k1_policy *current_policy = NULL;

    while(current_policy_node) {
        current_policy = (struct k1_policy *)current_policy_node->data;

        if(current_policy->auth_map_pair)
            err =
                register_auth_pair_to_map(skel, current_policy->auth_map_pair);
        if(err) {
            logger(
                LOG_ERROR,
                stdout,
                "error while registering auth pair: %s\n",
                strerror(errno));
            break;
        }

        if(current_policy->verdict_map_user_pair &&
           current_policy->verdict_sub_type != K1_VERDICT_MAP_SID)
            err = register_verdict_pair_to_map(
                skel, current_policy->verdict_map_user_pair);
        if(err) {
            logger(
                LOG_ERROR,
                stdout,
                "error while registering verdict pair: %s\n",
                strerror(errno));
            break;
        }
        if(current_policy->exception_linked_list)
            err = register_exceptions_pathname(
                skel,
                current_policy->exception_linked_list,
                policies_head_node->euid,
                current_policy->verdict_map_user_pair->key.verdict_hook, /**/
                current_policy->verdict_sub_type);
        if(err) {
            logger(
                LOG_ERROR,
                stdout,
                "error while registering exceptions: %s\n",
                strerror(errno));
            break;
        }

        if(current_policy->verdict_sub_type == K1_VERDICT_MAP_SID)
            err = register_user_wanting_sid_verdict(
                skel, policies_head_node->euid);
        if(err) {
            logger(
                LOG_ERROR,
                stdout,
                "error while registering user wanting sid verdict: %s\n",
                strerror(errno));
            break;
        }

        err = register_user(skel, policies_head_node->euid);
        if(err) {
            logger(
                LOG_ERROR,
                stdout,
                "error while registering user: %s\n",
                strerror(errno));
            break;
        }

        current_policy_node = current_policy_node->next;
    }

    return err;
}

int register_user(struct bpf_progs *skel, uid_t euid)
{
    return bpf_map__update_elem(
        skel->maps.registered_euids_map_hash,
        &euid,
        sizeof(struct k1_users_having_sid_verdict_map_key),
        &euid,
        sizeof(DUMMY_MAP_VALUE_T),
        BPF_ANY);
}

int register_user_wanting_sid_verdict(struct bpf_progs *skel, uid_t euid)
{
    return bpf_map__update_elem(
        skel->maps.users_having_sid_verdict_map_hash,
        &euid,
        sizeof(struct k1_users_having_sid_verdict_map_key),
        &euid,
        sizeof(DUMMY_MAP_VALUE_T),
        BPF_ANY);
}

int register_auth_pair_to_map(
    struct bpf_progs *skel, struct k1_auth_map_pair *auth_map_pair)
{
    int err = 0;

    err = bpf_map__update_elem(
        skel->maps.auth_map_hash,
        &auth_map_pair->key,
        sizeof(auth_map_pair->key),
        &auth_map_pair->value,
        sizeof(auth_map_pair->value),
        0);
    if(err) {
        printf("%s\n", strerror(errno));
        goto finish;
    }

finish:
    return err;
}

int register_verdict_pair_to_map(
    struct bpf_progs *skel,
    struct k1_verdict_map_user_pair *verdict_map_user_pair)
{
    int err = 0;

    err = bpf_map__update_elem(
        skel->maps.verdict_map_user_hash,
        &verdict_map_user_pair->key,
        sizeof(verdict_map_user_pair->key),
        &verdict_map_user_pair->value,
        sizeof(verdict_map_user_pair->value),
        0);
    if(err) {
        printf("%s\n", strerror(errno));
        goto finish;
    }

finish:
    return err;
}

int register_exceptions_pathname(
    struct bpf_progs *skel,
    struct k1_node *head,
    uid_t euid,
    enum K1_VERDICT_HOOK verdict_hook,
    enum K1_VERDICT_MAP_TYPE verdict_map_type)
{
    struct k1_node *current_node = head;
    int err = 0;
    while(current_node) {
        struct k1_parsed_exception_pathname *current_parsed_exception =
            current_node->data;
        logger(
            LOG_DEBUG,
            stdout,
            "exception pathname %s, is_whitelist: %d\n",
            current_parsed_exception->pathname,
            current_parsed_exception->is_whitelist);
        err = register_exception_pathname(
            skel,
            current_parsed_exception->pathname,
            euid,
            verdict_hook,
            verdict_map_type,
            current_parsed_exception->is_whitelist);
        if(err) {
            printf("%s\n", strerror(errno));
            goto finish;
        }
        logger(
            LOG_DEBUG,
            stdout,
            "excluding %s: is_whitelist: %d\n",
            current_parsed_exception->pathname,
            current_parsed_exception->is_whitelist);
        current_node = current_node->next;
    }
finish:
    return err;
}
