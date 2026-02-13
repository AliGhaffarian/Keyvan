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

    struct k1_node *head_auth_map_pair;
    struct k1_node *head_verdict_map_user_pair;
    struct k1_node *head_parsed_exception_pathname = NULL;

    struct {
        uid_t current_uid;
    } parser_ctx ;

    int yylex(void);
    void yyerror(const char *s);
    struct k1_node *append_exception_pathname__pathname_is_whitelisted(struct k1_node *head, char *pathname, bool is_whitelist);
    void complete_exception_pathname_list(struct k1_node *head, uid_t uid, enum K1_VERDICT_HOOK verdict_hook, enum K1_VERDICT_MAP_TYPE verdict_map_type);
%}

%token UID
%token <ival> NUMBER
%token PATHNAME
%token <str> STRING
%token <str> SERIAL
%token TYPE
%token EXECVE
%token USB
%token AUTH
%token VERDICT
%token VERDICT_SUB_TYPE
%token WHITELISTS
%token BLACKLISTS

%union {
    int number;
    char *str;
    int ival;
    uid_t uidval;

    struct k1_auth_cred_execve *auth_cred_execve;
    struct k1_auth_cred_usb *auth_cred_usb;

    struct k1_verdict_map_user_key *verdict_map_user_key;

    struct k1_auth_map_pair *auth_map_pair;
    struct k1_verdict_map_user_pair *verdict_map_user_pair;

    struct k1_node *node;
}

%type <void> uid
%type <str> pathname

%type <auth_cred_execve> execve_auth_fields
%type <auth_cred_execve> execve_auth_struct

%type <auth_cred_usb> usb_auth_fields
%type <auth_cred_usb> usb_auth_struct

%type <auth_map_pair> auth_policy_specs
%type <void> auth_policy

%type <verdict_map_user_pair> execve_verdict_struct
%type <verdict_map_user_pair> verdict_policy_specs
%type <void> verdict_policy

%type <void> policy
%type <void> policies
%type <void> entry

%type <node> whitelists
%type <node> blacklists
%type <node> exceptions

%%
uid: UID ':' NUMBER { parser_ctx.current_uid = $3; };

pathname: PATHNAME ':' STRING { $$ = strdup($3); } ;

execve_auth_fields:
                  pathname
                  {
                  struct k1_auth_cred_execve *self = malloc(sizeof(*self));
                  int pathname_strlen = strlen($1);
                  if(!self) yyerror("nomem");

                  if(pathname_strlen >= K1_BPF_STRING_MAXSIZE - 1)
                        yyerror("bpf string exceeds max len");

                  memcpy(self->pathname, $1, pathname_strlen);
                  self->pathname[pathname_strlen] = 0;

                  free($1);
                  $$ = self;
                  };

execve_auth_struct: TYPE ':' EXECVE execve_auth_fields { $$ = $4; };

usb_auth_fields:
               SERIAL
               {
                struct k1_auth_cred_usb *self = malloc(sizeof(*self));
                int serial_strlen = strlen($1);
                if(!self) yyerror("nomem");

                if(serial_strlen >= K1_BPF_STRING_MAXSIZE - 1)
                    yyerror("bpf string exceeds max len");

                memcpy(self->serial, $1, serial_strlen);
                self->serial[serial_strlen] = 0;

                free($1);
                $$ = self;
               };

usb_auth_struct: TYPE ':' USB usb_auth_fields { $$ = $4; };

auth_policy_specs:
                 execve_auth_struct {
                 struct k1_auth_map_pair *self = malloc(sizeof(*self));
                 if(!self) yyerror("nomem");

                 memcpy(&self->value.record.auth_cred_execve, $1, sizeof(*$1));
                 free($1);

                 self->value.record.auth_type = K1_AUTH_TYPE_EXECVE;
                 self->key.auth_type = K1_AUTH_TYPE_EXECVE;

                 $$ = self;
                 }
                 | usb_auth_struct
                 {
                 struct k1_auth_map_pair *self = malloc(sizeof(*self));
                 if(!self) yyerror("nomem");

                 memcpy(&self->value.record.auth_cred_usb, $1, sizeof(*$1));
                 free($1);

                 self->value.record.auth_type = K1_AUTH_TYPE_USB;
                 self->key.auth_type = K1_AUTH_TYPE_USB;

                 $$ = self;
                 };

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
                $$ = append_exception_pathname__pathname_is_whitelisted(NULL, strdup($1), 1);
          }
          | blacklists STRING
          {
                append_exception_pathname__pathname_is_whitelisted($1, strdup($2), 0);
                $$ = $1;
          }
;

exceptions:
          %empty { $$ = NULL; }
          | WHITELISTS ':' whitelists { $$ = $3; }
          | BLACKLISTS ':' blacklists { $$ = $3; }

auth_policy:
            AUTH ':' '{' auth_policy_specs VERDICT_SUB_TYPE ':' STRING VERDICT ':' '{' verdict_policy_specs exceptions '}' '}'
            {
            struct k1_auth_map_pair *current_auth_map_pair = $4;
            struct k1_verdict_map_user_pair *current_verdict_map_user_pair = $11;
            struct k1_node *exceptions = $12;

            current_auth_map_pair->key.uid = parser_ctx.current_uid;
            current_auth_map_pair->value.verdict_entry_lookup_info.verdict_hook = current_verdict_map_user_pair->key.verdict_hook;
            current_auth_map_pair->value.verdict_entry_lookup_info.verdict_map_type = enum_from_string_k1_verdict_map_type($7);
            if(current_auth_map_pair->value.verdict_entry_lookup_info.verdict_map_type == _K1_VERDICT_MAP_UNSPEC){
                    printf("got verdict_sub_type:%s\n", $7);
                    yyerror("unknown verdict_sub_type");
                    }

            // handle exceptions
            complete_exception_pathname_list(
                exceptions,
                parser_ctx.current_uid,
                current_verdict_map_user_pair->key.verdict_hook,
                current_auth_map_pair->value.verdict_entry_lookup_info.verdict_map_type
                );
            k1_linked_list_append(&head_parsed_exception_pathname, &exceptions);

            // handle user verdicts
            current_verdict_map_user_pair->key.uid = parser_ctx.current_uid;
            if(current_auth_map_pair->value.verdict_entry_lookup_info.verdict_map_type != K1_VERDICT_MAP_SID){
                    struct k1_node *verdict_node = k1_make_node((void **)&current_verdict_map_user_pair);
                    if(!verdict_node) yyerror("nomem");
                    k1_linked_list_append(&head_verdict_map_user_pair, &verdict_node);
            }

            struct k1_node *auth_node = k1_make_node((void **)&current_auth_map_pair);
            if(!auth_node) yyerror("nomem");

            k1_linked_list_append(&head_auth_map_pair, &auth_node);
            }
            | AUTH ':' '{' auth_policy_specs '}'
            {
            struct k1_auth_map_pair *current_auth_map_pair = $4;
            current_auth_map_pair->key.uid = parser_ctx.current_uid;
            struct k1_node *auth_node = k1_make_node((void **)&current_auth_map_pair);
            if(!auth_node) yyerror("nomem");
            k1_linked_list_append(&head_auth_map_pair, &auth_node);
            };

execve_verdict_struct: TYPE ':' EXECVE
                   {
                   struct k1_verdict_map_user_pair *self = malloc(sizeof(*self));
                   if(!self) yyerror("nomem");
                   self->key.verdict_hook = K1_VERDICT_HOOK_LSM_BPRM_CREDS_FOR_EXEC;
                   $$ = self;
                   };

verdict_policy_specs: execve_verdict_struct;

verdict_policy: VERDICT ':' '{' verdict_policy_specs exceptions'}'
            {
            struct k1_verdict_map_user_pair *current_verdict_map_user_pair = $4;
            struct k1_node *exceptions = $5;
            current_verdict_map_user_pair->key.uid = parser_ctx.current_uid;
            struct k1_node *verdict_register = k1_make_node((void **)&current_verdict_map_user_pair);
            if(!verdict_register) yyerror("nomem");
            k1_linked_list_append(&head_verdict_map_user_pair, &verdict_register);

            // handle exceptions
            complete_exception_pathname_list(
                exceptions,
                parser_ctx.current_uid,
                current_verdict_map_user_pair->key.verdict_hook,
                K1_VERDICT_MAP_SID // default value for verdict that's not associated with a auth checker
                );
            k1_linked_list_append(&head_parsed_exception_pathname, &exceptions);
            };

policy: auth_policy | verdict_policy;

policies: policy | %empty;

entry:
    %empty
    | entry uid policies;

%start entry;
%%
void yyerror(const char *s) {
    fprintf(stderr, "Parse error: %s\n", s);
    exit(1);
}
struct k1_node *append_exception_pathname__pathname_is_whitelisted(struct k1_node *head, char *pathname, bool is_whitelist){
            struct k1_parsed_exception_pathname *elem = malloc(sizeof(*elem));
            if(!elem) yyerror("nomem");

            elem->is_whitelist = 1;
            elem->pathname = pathname;

            struct k1_node *node = k1_make_node((void **)&elem);
            if(!node) yyerror("nomem");

            if(head != NULL)
                k1_linked_list_append(&head, &node);

            return node;
}
void complete_exception_pathname_list(struct k1_node *head, uid_t uid, enum K1_VERDICT_HOOK verdict_hook, enum K1_VERDICT_MAP_TYPE verdict_map_type){
            struct k1_node *current = head;
            while(current != NULL){
                struct k1_parsed_exception_pathname *elem = current->data;
                elem->uid = uid;
                elem->verdict_hook = verdict_hook;
                elem->verdict_map_type = verdict_map_type;

                current = current->next;
            }
}
