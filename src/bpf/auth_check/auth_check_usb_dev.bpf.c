// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef __BPF__
#define __BPF__
#endif

#include <k1_bpf_util.h>
#include <k1_limits.h>
#include <k1_map.h>

static const enum K1_AUTH_TYPE const_auth_type_usb = K1_AUTH_TYPE_USB;

SEC("fentry/usb_create_sysfs_dev_files")
int BPF_PROG(auth_check_usb_create_sysfs, struct usb_device *udev) {
    if(!udev->serial)
        return 0;

    bpf_printk("connected udev: %s", udev->serial);

    struct k1_auth_map_key key = {
        .uid = INVALID_UID,
        .auth_type = K1_AUTH_TYPE_USB,
    };
    struct k1_auth_record *auth_record = k1_bpf_lookup_auth_record(&key);

    if(!auth_record)
        return 0;

    k1_change_user_auth_state(
        auth_record->verdict_hook, key.uid, K1_FLAG_CHANGE_SET);

    auth_record->is_authenticated = 1;

    return 0;
}

SEC("fentry/usb_remove_sysfs_dev_files")
int BPF_PROG(auth_check_usb_remove_sysfs, struct usb_device *udev) {

    if(!udev->serial)
        return 0;

    bpf_printk("disconnected udev: %s", udev->serial);

    struct k1_auth_map_key key = {
        .uid = INVALID_UID,
        .auth_type = K1_AUTH_TYPE_USB,
    };
    struct k1_auth_record *auth_record = k1_bpf_lookup_auth_record(&key);

    if(!auth_record)
        return 0;

    k1_change_user_auth_state(
        auth_record->verdict_hook, key.uid, K1_FLAG_CHANGE_SET);

    auth_record->is_authenticated = 0;

    return 0;
}

char __license[] SEC("license") = "GPL";
