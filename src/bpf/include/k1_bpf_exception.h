#ifndef K1_BPF_EXCEPTION
#define K1_BPF_EXCEPTION

#ifndef __BPF__
#define __BPF__
#endif

// clang-format off
#include <vmlinux.h>
// clang-format on

#include <helper.h>
#include <k1_bpf_util.h>
#include <k1_map.h>
#include <k1_map_pairs.h>
#include <verdict_record.h>

__always_inline enum K1_VERDICT_ACTION k1_bpf_handle_exception_pathname(
    enum K1_VERDICT_HOOK verdict_hook,
    enum K1_VERDICT_MAP_TYPE verdict_map_type,
    struct file *f,
    dev_t s_dev,
    uid_t uid)
{
    __u8 hash[SHA256_STR_SIZE / 2] = {0};
    struct k1_exception_map_pathname_value *value = NULL;
    enum hash_algo h_algo;
    struct k1_trust_map_file2sha256_value *trust_map_file2sha256_value = NULL;
    struct k1_trust_map_file2sha256_key trust_map_file2sha256_key = {0};
    struct k1_exception_map_pathname_key exception_map_pathname_key = {0};

    trust_map_file2sha256_key.inode_no = f->f_inode->i_ino;
    trust_map_file2sha256_key.s_dev = s_dev;

    exception_map_pathname_key.verdict_hook = verdict_hook;
    exception_map_pathname_key.verdict_map_type = verdict_map_type;
    exception_map_pathname_key.inode_no = f->f_inode->i_ino;
    exception_map_pathname_key.s_dev = s_dev;
    exception_map_pathname_key.uid = uid;

    value = bpf_map_lookup_elem(
        &exception_map_pathname_hash, &exception_map_pathname_key);
    if(!value) // no exception is registered
        return K1_VERDICT_NOOP;

    h_algo = bpf_ima_file_hash(f, &hash, sizeof(hash));

    if(h_algo != HASH_ALGO_SHA256)
        return K1_VERDICT_NOOP;

    trust_map_file2sha256_value = bpf_map_lookup_elem(
        &trust_map_file2sha256_hash, &trust_map_file2sha256_key);
    if(!trust_map_file2sha256_value) {
        bpf_printk("no hash for exception");
        return K1_VERDICT_NOOP;
    }

    // check hash only if is whitelist
    if(value->is_whitelist &&
       __builtin_memcmp(
           hash, trust_map_file2sha256_value->sha256, sizeof(hash))) {
        bpf_printk("exception hash mismatch");
        return K1_VERDICT_NOOP;
    }

    if(value->is_whitelist)
        return K1_VERDICT_ALLOW;
    if(!value->is_whitelist)
        return K1_VERDICT_DENY;

    bpf_printk("reached unreachable code");
    // should be unreachable
    return K1_VERDICT_NOOP;
}
#endif
