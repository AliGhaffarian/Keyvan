%{
#include "parser.tab.h"
%}

%s BEGIN_SERIAL_MATCH

%option noyywrap

str [a-zA-Z0-9_/.-]+
%%

#.*\n

"euid"               { return EUID; }

"auth"              { return AUTH; }
"verdict"           { return VERDICT; }

"type"              { return TYPE; }
"execve"            { return EXECVE; }
"usb"               { return USB; }

"whitelists"        {return WHITELISTS;}
"blacklists"        {return BLACKLISTS;}

"serial"[[:blank:]]*: { BEGIN(BEGIN_SERIAL_MATCH); }
<BEGIN_SERIAL_MATCH>{
    {str} {
        BEGIN(INITIAL);
        yylval.str = strdup(yytext);
        return SERIAL;
    }
}

"verdict_sub_type" {return VERDICT_SUB_TYPE;}

"pathname"        { return PATHNAME; }
[0-9]+              { yylval.number = atoi(yytext); return NUMBER; }
[a-zA-Z0-9_/.-]+    { yylval.str = strdup(yytext); return STRING; }

":"                 { return ':'; }
"{"                 { return '{'; }
"}"                 { return '}'; }

[ \t\n]+            ;
.                   { return yytext[0]; }
%%
