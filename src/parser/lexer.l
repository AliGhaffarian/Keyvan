%{
#include<k1_limits.h>
#include<errno.h>
#include<stdint.h>
#include<k1_map_pairs.h>
#include<enum_to_str_maps.h>
#include<parser_enum_maps.h>
#include "parser.tab.h"
void yyerror(const char *s);
#define is_blank_or_newline(ch) (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\0')
%}

%s BEGIN_SERIAL_MATCH
%s BEGIN_PATHNAME_MATCH
%s BEGIN_EUID_MATCH
%s BEGIN_VERDICT_SUB_TYPE_MATCH
%s BEGIN_AUTH_TYPE_MATCH
%s BEGIN_VERDICT_TYPE_MATCH
%s BEGIN_IS_AUTHENTICATED_MATCH

%option noyywrap

str [a-zA-Z0-9_/.-]+
hex 0x[[:digit:]]+
integer [[:digit:]]+

%%

#.*\n

euid[[:blank:]]*:[[:blank:]]* { BEGIN(BEGIN_EUID_MATCH); }
<BEGIN_EUID_MATCH>{
    {hex}[[:blank:]]* {
        //TODO: handle errors for numbers higher than u32
        BEGIN(INITIAL);
        char *endptr = NULL;
        uint64_t parsed = -1;

        parsed = strtoull(yytext + 2, &endptr, 0x10);
        if(errno)
            yyerror("error parsing number");
        if(!is_blank_or_newline(*endptr))
            yyerror("number didn't end with a blank");

        yylval.u32val = (uint32_t) parsed;
        return EUID;
    }

    {integer}[[:blank:]]* {
        BEGIN(INITIAL);
        char *endptr = NULL;
        uint64_t parsed = -1;

        parsed = strtoull(yytext, &endptr, 10);
        if(errno)
            yyerror("error parsing number");
        if(!is_blank_or_newline(*endptr))
            yyerror("number didn't end with a blank");

        yylval.u32val = (uint32_t) parsed;
        return EUID;
    }

    . {
        yyerror("number didn't match neither hex nor integer matching rules");
    }
}


"auth_type"[[:blank:]]*":"[[:blank:]]* { BEGIN(BEGIN_AUTH_TYPE_MATCH); }
<BEGIN_AUTH_TYPE_MATCH>{
    "execve"    { BEGIN(INITIAL); return AUTH_TYPE_EXECVE; }
    "usb"       { BEGIN(INITIAL); return AUTH_TYPE_USB; }
    .           { yyerror("invalid auth_type"); }
}

"verdict_type"[[:blank:]]*":"[[:blank:]]*  { BEGIN(BEGIN_VERDICT_TYPE_MATCH); }
<BEGIN_VERDICT_TYPE_MATCH>{
    "execve"    { BEGIN(INITIAL); return VERDICT_TYPE_EXECVE; }
    .           { yyerror("invalid verdict type"); }
}

"auth"[[:blank:]]*":"      { return AUTH; }
"verdict"[[:blank:]]*":"   { return VERDICT; }

"whitelists"            { return WHITELISTS; }
"blacklists"            { return BLACKLISTS; }

"serial"[[:blank:]]*":"[[:blank:]]* { BEGIN(BEGIN_SERIAL_MATCH); }
<BEGIN_SERIAL_MATCH>{
    {str} {
        BEGIN(INITIAL);
        yylval.str = strdup(yytext);

        if(strlen(yytext) >= K1_BPF_STRING_MAXSIZE - 1)
            yyerror("bpf string exceeds max len");

        return SERIAL;
    }
    . {
        yyerror("invalid serial");
    }
}

"verdict_sub_type"[[:blank:]]*":"[[:blank:]]* { BEGIN(BEGIN_VERDICT_SUB_TYPE_MATCH); }
<BEGIN_VERDICT_SUB_TYPE_MATCH>{
    {str} {
        BEGIN(INITIAL);
        enum K1_VERDICT_MAP_TYPE self = _K1_VERDICT_MAP_UNSPEC;
        self = parser_verdict_sub_type_str2enum(yytext);
        if(self == _K1_VERDICT_MAP_UNSPEC)
            yyerror("unknown verdict_sub_type");
        yylval.verdict_map_type = self;

        return VERDICT_SUB_TYPE;
    }

    . {
        yyerror("invalid verdict subtype");
    }
}

"pathname"[[:blank:]]*":"[[:blank:]]* { BEGIN(BEGIN_PATHNAME_MATCH); }
<BEGIN_PATHNAME_MATCH>{
    {str} {
        BEGIN(INITIAL);

        yylval.str = strdup(yytext);

        if(!yylval.str) yyerror("nomem");

        if(strlen(yylval.str) >= K1_BPF_STRING_MAXSIZE - 1)
            yyerror("bpf string exceeds max len");
        return PATHNAME;
    }
    . {
        yyerror("invalid pathname");
    }
}

"is_authenticated"[[:blank:]]*":"[[:blank:]] { BEGIN(BEGIN_IS_AUTHENTICATED_MATCH); }
<BEGIN_IS_AUTHENTICATED_MATCH>{
    "true" {
        BEGIN(INITIAL);

        yylval.boolval = 1;

        return IS_AUTHENTICATED;
    }
    "false" {
        BEGIN(INITIAL);

        yylval.boolval = 0;

        return IS_AUTHENTICATED;
    }
    . {
        yyerror("invalid boolval (must be \"true\" or \"false\")");
    }
}

{str}    { yylval.str = strdup(yytext); return STRING; }

":"                 { return ':'; }
"{"                 { return '{'; }
"}"                 { return '}'; }

[ \t\n]+            {}
.                   { return yytext[0]; }
%%
