#include <bpf/libbpf.h>
#include <bpf_progs.skel.h>
#include <k1/exception/pathname.h>
#include <k1/ima.h>
#include <k1_map_pairs.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>

/* https://elixir.bootlin.com/linux/v6.19-rc5/source/include/linux/kdev_t.h#L12
 * These macros differ from uapi counterparts, so if we want to make it
 * compatible with bpfside, we need to use the kerenelside version
 */

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev)    ((unsigned int)((dev) >> MINORBITS))
#define MINOR(dev)    ((unsigned int)((dev) & MINORMASK))
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))

// https://elixir.bootlin.com/linux/v6.19-rc5/source/include/linux/kdev_t.h
// kstat is copied to stat via  cp_new_stat that calls new_encode_dev, we decode
// our devs so bpfside is more efficient
static dev_t new_decode_dev(uint32_t dev)
{
    unsigned major = (dev & 0xfff00) >> 8;
    unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    return MKDEV(major, minor);
}

/**
 * 1. get the hash of pathname's file
 * 2. get inode number of the file
 * 3. get st_dev of file (same as sb->s_dev)
 * 4. update the exception map via uid + verdict_hook + verdict_map_type +
 * inode_no + sb
 * 5. update the file2sha256 map via inode_no + sb
 */
int register_exception_pathname(
    struct bpf_progs *skel,
    char *pathname,
    uid_t uid,
    enum K1_VERDICT_HOOK verdict_hook,
    enum K1_VERDICT_MAP_TYPE verdict_map_type,
    bool is_whitelist)
{
    struct k1_exception_map_pathname_pair exception_map_pair = {0};
    struct k1_trust_map_file2sha256_pair file2sha256_pair = {0};
    struct stat st = {0};
    sha256 hash = {0};
    int err = 0;
    char *pathname_real = NULL;

    // TODO: free this
    pathname_real = realpath(pathname, NULL);

    err = k1_ima_get_sha256(&hash, pathname_real);
    if(err)
        return err;

    err = stat(pathname_real, &st);
    if(err)
        return err;

    exception_map_pair.key.inode_no = st.st_ino;
    exception_map_pair.key.s_dev = new_decode_dev(st.st_dev);
    exception_map_pair.key.uid = uid;
    exception_map_pair.key.verdict_hook = verdict_hook;
    exception_map_pair.key.verdict_map_type = verdict_map_type;

    exception_map_pair.value.is_whitelist = is_whitelist;

    err = bpf_map__update_elem(
        skel->maps.exception_map_pathname_hash,
        &exception_map_pair.key,
        sizeof(exception_map_pair.key),
        &exception_map_pair.value,
        sizeof(exception_map_pair.value),
        BPF_ANY);
    if(err)
        return err;

    file2sha256_pair.key.s_dev = new_decode_dev(st.st_dev);
    file2sha256_pair.key.inode_no = st.st_ino;
    memcpy(file2sha256_pair.value.sha256, hash, sizeof(hash));

    err = bpf_map__update_elem(
        skel->maps.trust_map_file2sha256_hash,
        &file2sha256_pair.key,
        sizeof(file2sha256_pair.key),
        &file2sha256_pair.value,
        sizeof(file2sha256_pair.value),
        BPF_ANY);

    return err;
}
