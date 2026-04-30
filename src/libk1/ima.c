#include <assert.h>
#include <enum_to_str_maps.h>
#include <errno.h>
#include <helper.h>
#include <k1/ima.h>
#include <k1/logger.h>
#include <linux/hash_info.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *fmt_proc_cmdline_ima_hash = "ima_hash=%63s";
const char *pathname_ima_runtime_measurements_sha256 =
    "/sys/kernel/security/ima/ascii_runtime_measurements_sha256";

int k1_ima_current_hash_algo()
{
    char buf[64] = {0};
    FILE *cmdline = fopen("/proc/cmdline", "r");

    setvbuf(cmdline, NULL, _IONBF, 0);
    int matched = fscanf(cmdline, fmt_proc_cmdline_ima_hash, buf);

    fclose(cmdline);

    if(matched == 0)
        return HASH_ALGO_SHA1;
    for(int i = 0; i < HASH_ALGO__LAST; i++)
        if(!strcmp(hash_algo_name[i], buf))
            return i;

    // should be unreachable
    return -1;
}

int k1_ima_get_sha256(sha256 *hash, char *pathname)
{
    int ret = 0;
    int err = 0;
    char log_hash_buf[SHA256_STR_SIZE] = {0};
    char *captured_pathname = NULL;
    int matched = 0;
    char *line = NULL;
    size_t line_size = 0;

    FILE *hash_log = fopen(pathname_ima_runtime_measurements_sha256, "r");
    if(!hash_log) {
        logger(
            LOG_ERROR,
            stdout,
            "failed to get hash log, check if you're running as root and "
            "cmdline contains ima_hash=sha256\n");
        errno = EPERM;
        ret = 1;
        goto end;
    }

    while((getline(&line, &line_size, hash_log)) != EOF) {
        matched = sscanf(
            line,
            "%*s %*s %*s sha256:%s %ms",
            log_hash_buf,
            &captured_pathname);

        assert(matched == 2);

        if(strcmp(captured_pathname, pathname) == 0)
            break;
    }

    free(line);

    if(strcmp(captured_pathname, pathname)) {
        logger(
            LOG_WARN,
            stdout,
            "%s doesn't have a hash logged, please trigger it's measurement "
            "according to your ima policy\n",
            pathname);
        errno = ENOENT;
        ret = 1;
        goto end;
    } else {
        logger(
            LOG_DEBUG,
            stdout,
            "hash of pathname:%s is %s\n",
            pathname,
            log_hash_buf);
    }

    err = sha256_hex_to_bytes(log_hash_buf, (char *)hash);
    assert(err == 0);

end:
    fclose(hash_log);
    free(captured_pathname);
    return ret;
}
