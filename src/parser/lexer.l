%{
#include "parser.tab.h"
%}

%%

#.*\n

"uid"               { return UID; }

"auth"              { return AUTH; }
"verdict"           { return VERDICT; }

"type"              { return TYPE; }
"execve"            { return EXECVE; }
"usb"               { return USB; }

"serial"            { return SERIAL; }

"pathname"        { return PATHNAME; }
[0-9]+              { yylval.number = atoi(yytext); return NUMBER; }
[a-zA-Z0-9_/.-]+    { yylval.str = strdup(yytext); return STRING; }

":"                 { return ':'; }
"{"                 { return '{'; }
"}"                 { return '}'; }

[ \t\n]+            ;
.                   { return yytext[0]; }
%%

int yywrap(void) { return 1; }
