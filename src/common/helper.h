#ifndef K1_HELPER
#define K1_HELPER

#ifndef __BPF__
#include <sys/cdefs.h>
#include <sys/types.h>
#endif

#define _STR(x) #x
#define STR(x)  _STR(x)

/**
 * uid is unsigned, if we don't mark -1 as invalid it may get confusing
 */
#define INVALID_UID       -1
#define INVALID_SESSIONID -1

#define NBITS_MASK(n)  (((1ULL << n) - 1))
#define NBYTES_MASK(n) (NBITS_MASK(n * 8))

#define SHA256_STR_SIZE 64

// Helper function to convert a single hex character to its integer value
__always_inline int hex_char_to_int(char c)
{
    if(c >= '0' && c <= '9')
        return c - '0';
    if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

__always_inline int sha256_hex_to_bytes(const char* hex_str, char* byte_array)
{
    for(size_t i = 0; i < SHA256_STR_SIZE; i += 2) {
        int high = hex_char_to_int(hex_str[i]);
        if(high == -1)
            return -1;
        int low = hex_char_to_int(hex_str[i + 1]);
        if(low == -1)
            return -1;

        if(high == -1 || low == -1)
            return -1; // Invalid hex character

        byte_array[i / 2] = (char)((high << 4) | low);
    }
    return 0;
}
#endif
