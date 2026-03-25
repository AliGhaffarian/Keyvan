%{
    #include <k1/linked_list.h>
    #include <stdio.h>
    #include <sys/types.h>
    #include <string.h>
    #include <auth_record.h>
    #include <k1_map_pairs.h>
    #include <stdlib.h>
    #include <k1_limits.h>
    #include <enum_to_str_maps.h>
    #include <stdbool.h>
    #include <parser_structs.h>
    #include <stdint.h>

    struct k1_node *ruleset_linked_list = NULL;

    int yylex(void);
    void yyerror(const char *s);
    struct k1_node *append_exception_pathname__pathname_is_whitelisted(struct k1_node *head, char *pathname, bool is_whitelist);
%}

%token <u32val> EUID
%token <str>  PATHNAME
%token <str>  STRING
%token <str>  SERIAL
%token EXECVE
%token USB
%token AUTH
%token VERDICT
%token <verdict_map_type> VERDICT_SUB_TYPE
%token WHITELISTS
%token BLACKLISTS
%token AUTH_TYPE_USB
%token AUTH_TYPE_EXECVE
%token VERDICT_TYPE_EXECVE

%union {
    int number;
    char *str;
    uint32_t u32val;
    uid_t euidval;

    enum K1_VERDICT_MAP_TYPE verdict_map_type;

    struct k1_auth_cred_execve *auth_cred_execve;
    struct k1_auth_cred_usb *auth_cred_usb;
    struct k1_auth_record *auth_record;

    struct k1_verdict_map_user_key *verdict_map_user_key;

    struct k1_auth_map_pair *auth_map_pair;
    struct k1_verdict_map_user_pair *verdict_map_user_pair;

    struct k1_node *node;

    struct rule_verdict_block_fields *parsed_verdict_block_fields;
    struct rule_auth_block_fields *parsed_auth_block_fields;
    struct k1_policies_head_node *policies_head_node;
    struct k1_policy *policy;
}

%type <u32val> euid

%type <auth_cred_execve> execve_auth_struct_field
%type <auth_cred_execve> execve_auth_struct

%type <auth_cred_usb> usb_auth_struct_field
%type <auth_cred_usb> usb_auth_struct

%type <auth_record> auth_record
%type <parsed_auth_block_fields> auth_block_field
%type <parsed_auth_block_fields> auth_block_fields
%type <policy> auth_policy

%type <verdict_map_user_pair> execve_verdict_struct
%type <parsed_verdict_block_fields> verdict_block_field
%type <parsed_verdict_block_fields> verdict_block_fields
%type <policy> verdict_policy

%type <policy> policy   // completes the incomplete structures, such as keys and exception lists
%type <node> policies   //linked list of policies
%type <node> entry      //linked list of ruleset heads

%type <node> whitelists
%type <node> blacklists
%type <node> exception_list
%type <node> exception_lists

%%
euid: EUID { $$ = $1; };

execve_auth_struct_field:
                AUTH_TYPE_EXECVE
                {
                    $$ = NULL;
                }
                | PATHNAME
                {
                    struct k1_auth_cred_execve *self = calloc(1, sizeof(*self));
                    int pathname_strlen = strlen($1);

                    if(!self) yyerror("failed to allocate self for pathname field of execve_auth_struct");

                    memcpy(self->pathname, $1, pathname_strlen);
                    self->pathname[pathname_strlen] = 0;

                    free($1);
                    $$ = self;
                }
;

execve_auth_struct:
                execve_auth_struct_field
                {
                    $$ = $1;
                }
                | execve_auth_struct execve_auth_struct_field
                {
                    struct k1_auth_cred_execve *self = $1;
                    if($2){
                        free(self);
                        self = $2; // currently execve_auth_struct has only one field, so we just need to copy it
                    }
                    $$ = self;
                }
;

usb_auth_struct_field:
                AUTH_TYPE_USB
                {
                    $$ = NULL;
                }
                | SERIAL
                {
                    struct k1_auth_cred_usb *self = calloc(1, sizeof(*self));
                    int serial_strlen = strlen($1);

                    if(!self) yyerror("failed to allocate self for serial field of usb_auth_struct");

                    memcpy(self->serial, $1, serial_strlen);
                    self->serial[serial_strlen] = 0;

                    free($1);
                    $$ = self;
                }
;

usb_auth_struct:
                usb_auth_struct_field
                {
                    $$ = $1;
                }
                | usb_auth_struct usb_auth_struct_field
                {
                    struct k1_auth_cred_usb *self = $1;
                    if($2){
                        free(self);
                        self = $2; // currently usb_auth_struct has only one field, so we just need to copy it
                    }
                    $$ = self;
                }
;

auth_record:
                execve_auth_struct
                {
                    struct k1_auth_record *self = calloc(1, sizeof(*self));
                    struct k1_auth_cred_execve *parsed_execve_struct = $1;

                    if(!parsed_execve_struct) yyerror("invalid execve auth info");
                    if(!self) yyerror("failed to allocate self for auth_record");

                    memcpy(&self->auth_cred_execve, parsed_execve_struct, sizeof(*parsed_execve_struct));
                    free(parsed_execve_struct);

                    self->auth_type = K1_AUTH_TYPE_EXECVE;

                    $$ = self;
                }
                | usb_auth_struct
                {
                    struct k1_auth_record *self = calloc(1, sizeof(*self));
                    struct k1_auth_cred_usb *parsed_usb_struct = $1;

                    if(!parsed_usb_struct) yyerror("invalid usb auth info");
                    if(!self) yyerror("failed to allocate self for auth_record");

                    memcpy(&self->auth_cred_usb, parsed_usb_struct, sizeof(*parsed_usb_struct));
                    free(parsed_usb_struct);

                    self->auth_type = K1_AUTH_TYPE_USB;

                    $$ = self;
                }
;

auth_block_field:
                auth_record
                {
                    struct rule_auth_block_fields *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for auth_record of auth_block_field");
                    self->auth_record = $1;
                    $$ = self;
                }
                | verdict_policy
                {
                    struct rule_auth_block_fields *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for verdict_policy of auth_block_field");
                    self->verdict_policy = $1;
                    $$ = self;
                }
;

auth_block_fields:
                %empty
                {
                    $$ = NULL;
                }
                | auth_block_fields auth_block_field
                {
                    struct rule_auth_block_fields *self = $1;
                    struct rule_auth_block_fields *parsed_field = $2;
                    if(!self)
                        self = calloc(1, sizeof(*self));
                    if(!self)
                        yyerror("failed to allocate self for auth_block_field of auth_block_fields");

                    if(parsed_field->auth_record){
                        if(self->auth_record)
                            yyerror("duplicate auth record information");
                        self->auth_record = parsed_field->auth_record;
                    }

                    if(parsed_field->verdict_policy){
                        if(self->verdict_policy)
                            yyerror("duplicate verdictpolicy information");
                        self->verdict_policy = parsed_field->verdict_policy;
                    }

                    free(parsed_field);
                    $$ = self;
                }

auth_policy:
                AUTH '{' auth_block_fields '}'
                {
                    struct rule_auth_block_fields *parsed_auth_block_fields = $3;
                    struct k1_policy *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for auth_policy");

                    self->auth_map_pair = calloc(1, sizeof(struct k1_auth_map_pair));
                    if(!self->auth_map_pair) yyerror("failed to allocate auth_map_pair for auth_policy");

                    memcpy(&self->auth_map_pair->value.record,
                        parsed_auth_block_fields->auth_record,
                        sizeof(struct k1_auth_record)
                    );

                    if(parsed_auth_block_fields->verdict_policy){
                        struct k1_policy *verdict_policy = parsed_auth_block_fields->verdict_policy; // to cut some of the length of lines

                        self->verdict_map_user_pair
                            = verdict_policy->verdict_map_user_pair;
                        self->exception_linked_list = verdict_policy->exception_linked_list;

                        self->verdict_sub_type = verdict_policy->verdict_sub_type;

                        free(parsed_auth_block_fields->verdict_policy);
                        parsed_auth_block_fields->verdict_policy = NULL;
                    }
                    else {
                        self->verdict_sub_type = _K1_VERDICT_MAP_UNSPEC;
                        self->auth_map_pair->value.verdict_entry_lookup_info.verdict_map_type = _K1_VERDICT_MAP_UNSPEC;
                        self->auth_map_pair->value.verdict_entry_lookup_info.verdict_hook = _K1_VERDICT_HOOK_UNSPEC;
                    }

                    self->auth_map_pair->key.auth_type
                        = parsed_auth_block_fields->auth_record->auth_type;

                    $$ = self;
                }
;

whitelists:
                STRING
                {
                    // this is the head for the whole whitelist, and the next rule will be executed after this
                    $$ = append_exception_pathname__pathname_is_whitelisted(NULL, strdup($1), 1);
                }
                | whitelists STRING
                {
                    append_exception_pathname__pathname_is_whitelisted($1, strdup($2), 1);
                    $$ = $1;
                }
;

blacklists:
                STRING
                {
                    $$ = append_exception_pathname__pathname_is_whitelisted(NULL, strdup($1), 0);
                }
                | blacklists STRING
                {
                    append_exception_pathname__pathname_is_whitelisted($1, strdup($2), 0);
                    $$ = $1;
                }
;

exception_list:
                WHITELISTS ':'  whitelists    { $$ = $3; }
                | BLACKLISTS ':'  blacklists  { $$ = $3; }
;

exception_lists:
                exception_list
                {
                    $$ = $1;
                }
                | exception_lists exception_list
                {
                    k1_linked_list_append(&$1, &$2);
                    $$ = $1;
                }
;

execve_verdict_struct:
                VERDICT_TYPE_EXECVE
                {
                    struct k1_verdict_map_user_pair *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for execve_verdict_struct");

                    self->key.verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC;

                    $$ = self;
                }
;

verdict_block_field:
                execve_verdict_struct
                {
                    struct rule_verdict_block_fields *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for execve_verdict_struct of verdict_block_field");

                    self->verdict_map_user_pair = $1;

                    $$ = self;
                }
                | VERDICT_SUB_TYPE
                {
                    struct rule_verdict_block_fields *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for verdict_sub_type of verdict_block_field");

                    self->verdict_sub_type = $1;

                    $$ = self;
                }
                | exception_lists
                {
                    struct rule_verdict_block_fields *self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for exception_lists of verdict_block_field");

                    self->exception_linked_list = $1;

                    $$ = self;
                }
;

verdict_block_fields:
                %empty
                {
                    $$ = NULL;
                }
                | verdict_block_fields verdict_block_field
                {
                    struct rule_verdict_block_fields *self = $1;
                    struct rule_verdict_block_fields *parsed_field = $2;

                    if(!self) self = calloc(1, sizeof(*self));
                    if(!self) yyerror("failed to allocate self for verdict_block_field of verdict_block_fields");

                    if(parsed_field->exception_linked_list){
                        if(self->exception_linked_list){
                            k1_linked_list_append(&self->exception_linked_list, &parsed_field->exception_linked_list);
                        }
                        else
                            self->exception_linked_list = parsed_field->exception_linked_list;
                    }

                    if(parsed_field->verdict_sub_type){
                        if(self->verdict_sub_type)
                            yyerror("duplicate verdict sub type");
                        self->verdict_sub_type = parsed_field->verdict_sub_type;
                    }

                    if(parsed_field->verdict_map_user_pair){
                        if(self->verdict_map_user_pair)
                            yyerror("duplicate verdict information");
                        self->verdict_map_user_pair = parsed_field->verdict_map_user_pair;
                    }

                    free(parsed_field);
                    $$ = self;
                }
;

verdict_policy:
                VERDICT '{' verdict_block_fields '}'
                {
                    struct k1_policy *self = calloc(1, sizeof(*self));
                    struct rule_verdict_block_fields *parsed_verdict_block = $3;

                    if(!self) yyerror("failed to allocate self for verdict_policy");

                    self->verdict_sub_type = parsed_verdict_block->verdict_sub_type;
                    self->auth_map_pair = NULL;
                    self->verdict_map_user_pair = parsed_verdict_block->verdict_map_user_pair;
                    self->exception_linked_list = parsed_verdict_block->exception_linked_list;

                    free(parsed_verdict_block);

                    $$ = self;
                }
;

policy: auth_policy | verdict_policy;

policies:
                policy
                {
                    struct k1_node *self = k1_make_node((void **)&$1);
                    if(!self) yyerror("failed to allocate self for policies");

                    $$ = self;
                }
                | policies policy
                {
                    struct k1_node *self = $1;
                    struct k1_node *current_node = k1_make_node((void **)&$2);

                    if(!current_node) yyerror("failed to allocate current_node for policies");

                    k1_linked_list_append(&self, &current_node);

                    $$ = self;
                }
;

entry:
                euid policies
                {
                    struct k1_policies_head_node *current_head = calloc(1, sizeof(*current_head));
                    if(!current_head) yyerror("failed to allocate current_head for entry");

                    current_head->policies_linked_list = $2;
                    current_head->euid = $1;

                    ruleset_linked_list = k1_make_node((void **)&current_head);
                    if(!ruleset_linked_list) yyerror("failed to allocate ruleset_linked_list for entry");
                    $$ = ruleset_linked_list;
                }
                | entry euid policies
                {
                    struct k1_node *self = $1;
                    struct k1_policies_head_node *current_head = calloc(1, sizeof(*current_head));
                    struct k1_node *current_node = NULL;

                    if(!current_head) yyerror("failed to allocate current_head for entry");

                    current_head->policies_linked_list = $3;
                    current_head->euid = $2;

                    current_node = k1_make_node((void **)&current_head);
                    if(!current_node) yyerror("failed to allocate current_node for entry");

                    k1_linked_list_append(&self, &current_node);

                    $$ = self;
                }
;

%start entry;
%%
void yyerror(const char *s) {
    fprintf(stderr, "Parse error: %s\n", s);
    exit(1);
}
struct k1_node *append_exception_pathname__pathname_is_whitelisted(struct k1_node *head, char *pathname, bool is_whitelist){
    struct k1_parsed_exception_pathname *elem = calloc(1, sizeof(*elem));
    if(!elem) yyerror("nomem");

    elem->is_whitelist = is_whitelist;
    elem->pathname = pathname;

    struct k1_node *node = k1_make_node((void **)&elem);
    if(!node) yyerror("nomem");

    if(head != NULL)
        k1_linked_list_append(&head, &node);

    return node;
}
