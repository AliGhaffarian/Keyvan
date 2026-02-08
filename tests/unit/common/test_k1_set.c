// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
// clang-format on

#include <helper.h>
#include <k1_set.h>

#define SET_NTH_BIT(n) (((k1_set_batch_t)1) << (n));

void test_k1_set_clearelem_onbatch(void **state)
{
    // valid clear
    {
        k1_set_batch_t batch = -1;
        int err = 0;

        batch = 0b101;
        err = k1_set_clearelem_onbatch(&batch, 2);

        assert_int_equal(err, 0);
        assert_int_equal(errno, 0);
        assert_int_equal(batch, 0b001);
    }

    errno = 0;

    // invalid clear
    {
        k1_set_batch_t batch = -1;
        int err = 0;

        batch = 0b110;
        err = k1_set_clearelem_onbatch(&batch, K1_SET_ELEMS_IN_ONE_ENTRY);

        assert_int_equal(err, -1);
        assert_int_equal(errno, -EINVAL);
        assert_int_equal(batch, 0b110);
    }

    errno = 0;

    // max entry
    {
        k1_set_batch_t batch = -1;
        int err = 0;
        bool elem_val = 0;

        // manually clear the MSB
        k1_set_batch_t expect_batch_value =
            NBYTES_MASK(sizeof(k1_set_batch_t)) ^
            SET_NTH_BIT(K1_SET_ELEMS_IN_ONE_ENTRY - 1);

        err = k1_set_clearelem_onbatch(&batch, K1_SET_ELEMS_IN_ONE_ENTRY - 1);

        elem_val =
            batch & (((k1_set_batch_t)1) << (K1_SET_ELEMS_IN_ONE_ENTRY - 1)) ||
            0;

        assert_int_equal(elem_val, 0);
        assert_int_equal(err, 0);
        assert_int_equal(errno, 0);
        assert_int_equal(batch, expect_batch_value);
    }

    errno = 0;

    // zero'th elem
    {
        k1_set_batch_t batch = -1;
        int err = 0;

        batch = 0b101;
        err = k1_set_clearelem_onbatch(&batch, 0);

        assert_int_equal(err, 0);
        assert_int_equal(errno, 0);
        assert_int_equal(batch, 0b100);
    }
}

void test_k1_set_setelem(void **state)
{
    // valid set
    {
        struct k1_set set = {0};
        bool elemval = 0;
        int err = 0;

        err = k1_set_setelem(&set, 2, 1);
        assert_int_equal(errno, 0);

        elemval = k1_set_getelem(&set, 2);

        assert_int_equal(err, 0);
        assert_int_equal(elemval, 1);
    }

    errno = 0;

    // invalid set
    {
        struct k1_set set = {0};
        int err = 0;

        err = k1_set_setelem(&set, K1_SET_CAPACITY, 1);

        assert_int_equal(err, -1);
        assert_int_equal(errno, -EINVAL);
    }

    errno = 0;

    // max entry
    {
        struct k1_set set = {0};
        bool elemval = 0;
        int err = 0;

        err = k1_set_setelem(&set, K1_SET_CAPACITY - 1, 1);
        assert_int_equal(errno, 0);

        elemval = k1_set_getelem(&set, K1_SET_CAPACITY - 1);

        assert_int_equal(err, 0);
        assert_int_equal(elemval, 1);
    }

    errno = 0;

    // zero'th elem
    {
        struct k1_set set = {0};
        bool elemval = 0;
        int err = 0;

        err = k1_set_setelem(&set, 0, 1);
        assert_int_equal(errno, 0);

        elemval = k1_set_getelem(&set, 0);

        assert_int_equal(err, 0);
        assert_int_equal(elemval, 1);
    }
}

void test_k1_set_getelem(void **state)
{
    // valid get
    {
        struct k1_set set = {0};
        bool elemval = 0;
        bool manual_getelem = 0;

        k1_set_setelem(&set, 2, 1);
        elemval = k1_set_getelem(&set, 2);

        manual_getelem = (set.batches[0] & 0b100) || 0;

        assert_int_equal(errno, 0);
        assert_int_equal(manual_getelem, 1);
        assert_int_equal(elemval, manual_getelem);
    }

    errno = 0;

    // invalid get
    {
        struct k1_set set = {0};
        int err = 0;

        err = k1_set_getelem(&set, K1_SET_CAPACITY);

        assert_int_equal(err, (bool)-1);
        assert_int_equal(errno, -EINVAL);
    }

    errno = 0;

    // max entry
    {
        struct k1_set set = {0};
        bool elemval = 0;
        bool manual_getelem = 0;

        k1_set_setelem(&set, K1_SET_CAPACITY - 1, 1);
        elemval = k1_set_getelem(&set, K1_SET_CAPACITY - 1);

        manual_getelem = set.batches[_K1_BATCHES_SIZE - 1] || 0;

        assert_int_equal(errno, 0);
        assert_int_equal(manual_getelem, 1);
        assert_int_equal(elemval, manual_getelem);
    }

    errno = 0;

    // zero'th elem
    {
        struct k1_set set = {0};
        bool elemval = 0;
        bool manual_getelem = 0;

        k1_set_setelem(&set, 0, 1);
        elemval = k1_set_getelem(&set, 0);

        manual_getelem = set.batches[0] & 1;

        assert_int_equal(errno, 0);
        assert_int_equal(manual_getelem, 1);
        assert_int_equal(elemval, manual_getelem);
    }
}

int test_k1_set()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_k1_set_clearelem_onbatch),
        cmocka_unit_test(test_k1_set_setelem),
        cmocka_unit_test(test_k1_set_getelem),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
