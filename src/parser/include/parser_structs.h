#ifndef K1_PARSER_STRUCTS
#define K1_PARSER_STRUCTS

/**
 * @file Structures used in the exposed linked list, that represents the parsed
 * configuration.
 */

#include <k1/linked_list.h>
#include <k1_map_pairs.h>
#include <stdbool.h>
#include <sys/types.h>
#include <verdict_record.h>

struct k1_parsed_exception_pathname {
    char *pathname;
    bool is_whitelist;
};

struct k1_policies_head_node {
    uid_t euid;
    struct k1_node *policies_linked_list;
};

/**
 * @brief Describes a pair of associated auth and verdict configuration
 *
 * This struct is not complete by itself when parsed. it needs to be passed to
 * `complete_ruleset()` first in order to be usable. The reason is that some
 * information that are needed in `k1_policy.auth_map_pair`, are actually parsed
 * in the verdict block (stored in `k1_policy.verdict_map_user_pair`). so we
 * needed to either copy the needed fields within the parser, or by the user
 * code. the latter is chosen to avoid unnecessary complexity in the parser.
 */
struct k1_policy {
    struct k1_auth_map_pair *auth_map_pair;
    struct k1_verdict_map_user_pair *verdict_map_user_pair;
    enum K1_VERDICT_MAP_TYPE verdict_sub_type;
    struct k1_node *exception_linked_list;
};

struct rule_verdict_block_fields {
    struct k1_verdict_map_user_pair *verdict_map_user_pair;
    enum K1_VERDICT_MAP_TYPE verdict_sub_type;
    struct k1_node *exception_linked_list;
};

struct rule_auth_block_fields {
    struct k1_policy *verdict_policy;
    struct k1_auth_record *auth_record;
};

#endif
