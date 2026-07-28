#! /bin/python3
import enum
import tempfile
import subprocess
import errno
import time
import signal
import sys

from util import custom_logging
import logging
import os
FILENAME = os.path.basename(__file__).split('.')[0]
logger = custom_logging.getLogger(FILENAME)

import argparse

conf = {
    "k1cli_path": "k1cli",
    "k1cli_loglevel": "INFO",
    "popen_wait": 1,
    "k1cli_wait": 2
}

children : list = []

ap = argparse.ArgumentParser()
ap.add_argument("-l", "--log-level", help="test log level", default="INFO")
ap.add_argument("-k", "--k1cli-path", help="path to k1cli", default=conf["k1cli_path"])
ap.add_argument("-j", "--k1cli-log-level", help="log level of k1cli", default=conf["k1cli_loglevel"])
args = ap.parse_args()

logger.setLevel(args.log_level)
conf["k1cli_path"] = args.k1cli_path
conf["k1cli_loglevel"] = args.k1cli_log_level

TRUE_PROG = "/usr/bin/true"
LS_PROG = "/bin/ls"

def trigger_ima():
    logger.debug("triggering ima")
    pathnames = [
        "/bin/ip",
        TRUE_PROG,
        LS_PROG
    ]
    for pathname in pathnames:
        subprocess.run([pathname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def write_conf_to_tmpfile(conf: str):
    tmpfile_name = subprocess.check_output("mktemp").decode().strip()
    tmpfile = open(tmpfile_name, "w")

    wbytes = tmpfile.write(conf)
    tmpfile.flush()

    logger.debug(f"config filename: {tmpfile.name}, {wbytes=}")
    logger.debug(f"{open(tmpfile_name, 'r').read()}")

    return tmpfile

def run_k1cli(conf_file):
    logger.debug("running k1cli")
    k1cli = subprocess.Popen(
        [conf["k1cli_path"], "-c", conf_file.name, "-l", conf["k1cli_loglevel"]],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    try:
        k1cli.wait(conf["popen_wait"] + conf["k1cli_wait"])
    except:
        pass
    if k1cli.poll() is not None:
        logger.critical(f"couldn't run k1cli, returncode: {k1cli.returncode}")
        logger.critical(f"info on k1cli: {k1cli}")
        return None
    children.append(k1cli)
    return k1cli

def terminate_k1cli(k1cli: subprocess.Popen):
    children.remove(k1cli)

    k1cli.terminate()

    try:
        k1cli.wait(conf["k1cli_wait"])
    except:
        k1cli.kill()


def cleanup_n_exit(code):
    for child in children:
        logger.debug(f"cleaning up {child}")
        child.terminate()

    exit(code)

def do_shellscript_uid(script: list[list[str]], uid: int, start_new_session: bool = False)->list[int]:
    ret = [ 0 ] * len(script)

    pipe = os.pipe()
    f = os.fork()

    if f == 0:
        ret = [ 0 ] * len(script)

        os.setuid(uid)
        if start_new_session:
            os.setsid()

        for i,cmd in enumerate(script):
            try:
                logger.debug(f"sid: {os.getsid(0)}: running {' '.join(cmd)}")
                r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            except:
                r = 1
            ret[i] = r
        os.write(pipe[1], str(ret).encode())
        # in case execve failed
        exit(0)

    os.waitpid(f, 0)
    ret = eval(os.read(pipe[0], 128).decode())

    os.close(pipe[0])
    os.close(pipe[1])

    logger.debug(f"status of script {script} is {ret}")
    logger.debug(f"euid after script : {os.geteuid()}")
    return ret

def do_cmd_as_uid(cmd: list[str], uid: int, start_new_session: bool = False):
    return do_shellscript_uid([cmd], uid, start_new_session)[0]

def expect_cmd_fail_uid(cmd: list[str], uid: int, start_new_session: bool = False):
    expect_eperm = do_cmd_as_uid(cmd, uid, start_new_session)
    logger.debug(f"{expect_eperm=}")
    assert(expect_eperm != 0)

def expect_cmd_success_uid(cmd: list[str], uid: int, start_new_session: bool = False):
    expect_success = do_cmd_as_uid(cmd, uid, start_new_session)
    logger.debug(f"{expect_success=}")
    assert(expect_success == 0)


def test_execve_euid():
    global conf
    whitelist = TRUE_PROG
    blacklist = "/bin/ip"
    password = "/password"
    euid = 1000
    #simple case
    k1_conf = """
euid: <euid> #comment
#comment
auth: { #comment
    auth_type: execve #comment
    pathname: <password> #comment
    verdict: { #comment
        verdict_type: execve #comment
        verdict_sub_type: per_user #comment
        whitelists:
            <whitelists>
        blacklists:
            <blacklists>
    } #comment
} #comment
"""
    k1_conf = k1_conf.replace("<password>", password)\
    .replace("<whitelists>", whitelist)\
    .replace("<blacklists>", blacklist)\
    .replace("<euid>", str(euid))

    conf_file = write_conf_to_tmpfile(k1_conf)

    k1cli = run_k1cli(conf_file)
    if k1cli is None:
        return None
    logger.debug(k1cli)


    expect_cmd_success_uid([whitelist], euid)

    expect_cmd_fail_uid([LS_PROG], euid)
    expect_cmd_success_uid([LS_PROG], 5)
    expect_cmd_success_uid([LS_PROG], 0)

    dont_care = do_cmd_as_uid([password], euid)
    logger.debug(f"{dont_care=}")

    expect_cmd_success_uid([LS_PROG], euid)
    expect_cmd_success_uid([LS_PROG], 5)
    expect_cmd_success_uid([LS_PROG], 0)

    expect_cmd_fail_uid([blacklist], euid)

    conf_file.close()


    terminate_k1cli(k1cli)
    logger.info("passed")


def test_execve_sid():
    global conf
    #simple case
    whitelist = TRUE_PROG
    blacklist = "/bin/ip"
    password = "/password"
    euid = 1000

    script = [
        [LS_PROG],
        [password],
        [LS_PROG],
        [blacklist]
    ]

    #simple case
    k1_conf = """
euid: <euid> #comment
#comment
auth: { #comment
    auth_type: execve #comment
    pathname: <password> #comment
    verdict: { #comment
        verdict_sub_type: per_session #comment
        verdict_type: execve #comment
        whitelists:
            /bin/sh
            <whitelists>
        blacklists:
            <blacklists>
    } #comment
} #comment
"""

    k1_conf = k1_conf.replace("<password>", password)\
    .replace("<whitelists>", whitelist)\
    .replace("<blacklists>", blacklist)\
    .replace("<euid>", str(euid))

    conf_file = write_conf_to_tmpfile(k1_conf)

    k1cli = run_k1cli(conf_file)
    if k1cli is None:
        return None

    expect_cmd_success_uid([LS_PROG], 1000, start_new_session=False)
    expect_cmd_success_uid([whitelist], 1000, start_new_session=True)
    expect_cmd_fail_uid([LS_PROG], 1000, start_new_session=True)

    errors = do_shellscript_uid(script, euid, start_new_session = True)

    assert(errors[0] != 0) # before auth
    #errors[1] is at auth
    assert(errors[2] == 0) # after auth
    assert(errors[3] != 0) # black list

    errors = do_shellscript_uid(script, euid, start_new_session = True)

    assert(errors[0] != 0) # before auth
    #errors[1] is at auth
    assert(errors[2] == 0) # after auth
    assert(errors[3] != 0) # black list

    conf_file.close()

    terminate_k1cli(k1cli)
    logger.info("passed")

def test_default_is_authenticated_euid():
    global conf
    #simple case
    whitelist = TRUE_PROG
    blacklist = "/bin/ip"
    password = "/password"
    euid = 1000

    script = [
        [LS_PROG],
        [password],
        [LS_PROG],
        [blacklist]
    ]

    #simple case
    k1_conf = """
euid: <euid> #comment
#comment
auth: { #comment
    auth_type: execve #comment
    pathname: <password> #comment
    verdict: { #comment
        verdict_sub_type: per_user #comment
        verdict_type: execve #comment
        is_authenticated: true
        whitelists:
            /bin/sh
            <whitelists>
        blacklists:
            <blacklists>
    } #comment
} #comment
"""

    k1_conf = k1_conf.replace("<password>", password)\
    .replace("<whitelists>", whitelist)\
    .replace("<blacklists>", blacklist)\
    .replace("<euid>", str(euid))

    conf_file = write_conf_to_tmpfile(k1_conf)

    k1cli = run_k1cli(conf_file)
    if k1cli is None:
        return None

    expect_cmd_success_uid([LS_PROG], 1000, start_new_session=False)
    expect_cmd_success_uid([whitelist], 1000, start_new_session=False)
    expect_cmd_fail_uid([blacklist], 1000, start_new_session=False)

    # de-auth
    do_cmd_as_uid([password], euid, start_new_session = False)

    expect_cmd_fail_uid([LS_PROG], 1000, start_new_session=False)
    expect_cmd_success_uid([whitelist], 1000, start_new_session=False)
    expect_cmd_fail_uid([blacklist], 1000, start_new_session=False)

    conf_file.close()

    terminate_k1cli(k1cli)
    logger.info("passed")

if __name__ == "__main__":
    def sighandler(__, _):
        logger.info("got interrupted, cleaning up")
        cleanup_n_exit(1)

    signal.signal(signal.SIGINT, sighandler)
    if os.geteuid() != 0:
        logger.critical("run me as root")
        cleanup_n_exit(1)

    trigger_ima()
    test_execve_euid()
    test_execve_sid()
    test_default_is_authenticated_euid()

    cleanup_n_exit(0)
