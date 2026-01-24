#ifndef K1_HELPER
#define K1_HELPER

#define _STR(x) #x
#define STR(x)  _STR(x)

/**
 * uid is unsigned, if we don't mark -1 as invalid it may get confusing
 */
#define INVALID_UID -1

#endif
