@page pitfalls Pitfalls

@tableofcontents

# Pitfalls

These pitfalls are mostly about not getting locked out. If you are stuck, restarting your display manager or system as a whole will fix the issue.

## Exception rules

1. Don't put non executables in the exception lists
2. Execute the exception list before running Keyvan

## Execve Verdicts

### Desktop Environment Crash

This is very environment specific, in my experience whenever i tried to make a new window and Keyvan were to deny me of doing so, display manager stopped responding and i couldn't create new windows even if i authenticated, leaving me no choice but to restart the display manager.
This is probably less of an issue in terminal only environments.

### Per-session Authentications

If you want to use per-session mode for `execve` verdict, you need to whitelist all the programs that run in the sequence of running a terminal emulator. You will be locked out otherwise since you have no way to authenticate yourself.

per-session authentication is not suitable for desktop, gui environments, since gui applications don't know that they need to authenticate themselved, and therefore will most likely crash.

If you use i3 window manager along xfce terminal and zsh, the following whitelist will probably be enough for you.
```
/usr/bin/zsh
/usr/bin/sh
/usr/bin/i3-sensible-terminal
/bin/i3-sensible-terminal
/usr/bin/x-terminal-emulator
/bin/x-terminal-emulator
/usr/bin/xfce4-terminal
```
