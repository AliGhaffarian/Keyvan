#ifndef K1_SET
#define K1_SET

#ifdef __BPF__
#include <vmlinux.h>
#else
#include <linux/types.h>
#include <stdbool.h>
#endif

#include <errno.h>

typedef __u64 k1_set_batch_t;

#define _K1_BATCHES_SIZE 5

#define K1_SET_ELEMS_IN_ONE_ENTRY (sizeof(k1_set_batch_t) * 8)

#define K1_SET_CAPACITY (_K1_BATCHES_SIZE * K1_SET_ELEMS_IN_ONE_ENTRY)

#define K1_SET_BREAK_SET_NTH(entry_ptr, bit_position_ptr, nth)                 \
    do {                                                                       \
        *entry_ptr = nth / (K1_SET_ELEMS_IN_ONE_ENTRY);                        \
        *bit_position_ptr = nth % (K1_SET_ELEMS_IN_ONE_ENTRY);                 \
    } while(0)

struct k1_set {
    k1_set_batch_t batches[_K1_BATCHES_SIZE];
};

/**
 * @brief Clears a specific bit within a single batch entry.
 * This is a helper function that targets a bit relative to the start of the 
 * provided batch.
 *
 * @param batch        Pointer to the specific batch (word) to modify.
 * @param bit_position The bit index within the batch (0 to K1_SET_ELEMS_IN_ONE_ENTRY - 1).
 * @return int         0 on success, -1 if bit_position is out of bounds (sets errno to -EINVAL).
 */
__always_inline int
k1_set_clearelem_onbatch(k1_set_batch_t *batch, __u64 bit_position) {
    if(bit_position >= K1_SET_ELEMS_IN_ONE_ENTRY) {
        errno = -EINVAL;
        return -1;
    }
    k1_set_batch_t bit_position_value =
        *batch & (((k1_set_batch_t)1) << bit_position);
    *batch ^= bit_position_value;
    return 0;
}

/**
 * @brief Sets or clears the Nth element in the set.
 * Maps the global index @p nth to a specific batch and bit position, then 
 * updates it to the boolean @p value.
 *
 * @param set   Pointer to the k1_set structure.
 * @param nth   Index of the element to set.
 * @param value Value to store.
 * @return int  0 on success, -1 if nth exceeds capacity (sets errno to -EINVAL).
 */
__always_inline int k1_set_setelem(struct k1_set *set, __u64 nth, bool value) {
    __u64 entry;
    __u64 bit_position;

    if(nth >= K1_SET_CAPACITY) {
        errno = -EINVAL;
        return -1;
    }

    K1_SET_BREAK_SET_NTH(&entry, &bit_position, nth);

    k1_set_clearelem_onbatch(&set->batches[entry], bit_position);

    set->batches[entry] |= (value << bit_position);

    return 0;
}

/**
 * @brief Retrieves the value of the Nth element in the set.
 *
 * @param set Pointer to the k1_set structure.
 * @param nth The global index of the element to retrieve.
 * @return true if the bit is set, false otherwise. 
 * @note Sets errno to -EINVAL if nth is out of bounds.
 */
__always_inline bool k1_set_getelem(struct k1_set *set, __u64 nth) {
    __u64 entry;
    __u64 bit_position;
    bool ret;

    if(nth >= K1_SET_CAPACITY) {
        errno = -EINVAL;
        return -1;
    }

    K1_SET_BREAK_SET_NTH(&entry, &bit_position, nth);
    k1_set_batch_t bit_position_value =
        set->batches[entry] & (((k1_set_batch_t)1) << bit_position);

    ret = bit_position_value || 0;
    return ret;
}

#endif
