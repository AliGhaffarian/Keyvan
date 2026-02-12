#ifndef K1_IMA
#define K1_IMA

#include <linux/hash_info.h>
#include <stdint.h>

typedef uint_fast8_t sha256[32];

extern const char *fmt_ascii_runtime_measurements_sha256;
extern const char *fmt_proc_cmdline_ima_hash;
extern const char *pathname_ima_runtime_measurements_sha256;

int k1_ima_current_hash_algo();
int k1_ima_get_sha256(sha256 *hash, char *pathname);

#endif
