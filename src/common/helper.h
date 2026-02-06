#ifndef K1_HELPER
#define K1_HELPER

#define _STR(x) #x
#define STR(x)  _STR(x)

/**
 * uid is unsigned, if we don't mark -1 as invalid it may get confusing
 */
#define INVALID_UID       -1
#define INVALID_SESSIONID -1

#define NBITS_MASK(n)  (((1ULL << n) - 1))
#define NBYTES_MASK(n) (NBITS_MASK(n * 8))

#endif
