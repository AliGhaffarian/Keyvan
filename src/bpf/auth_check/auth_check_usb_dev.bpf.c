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
int BPF_PROG(auth_check_usb_create_sysfs, struct usb_device *udev)
{
    if(!udev->serial)
        return 0;

    bpf_printk("connected udev: %s", udev->serial);

    struct k1_auth_map_key key = {
        .uid = INVALID_UID,
        .auth_type = K1_AUTH_TYPE_USB,
    };
    struct k1_auth_map_value *elem = k1_bpf_auth_map_lookup(&key);

    if(!elem)
        return 0;

    k1_change_user_auth_state(
        &elem->verdict_entry_lookup_info, key.uid, K1_FLAG_CHANGE_SET);

    elem->is_authenticated = 1;

    return 0;
}

SEC("fentry/usb_remove_sysfs_dev_files")
int BPF_PROG(auth_check_usb_remove_sysfs, struct usb_device *udev)
{

    if(!udev->serial)
        return 0;

    bpf_printk("disconnected udev: %s", udev->serial);

    struct k1_auth_map_key key = {
        .uid = INVALID_UID,
        .auth_type = K1_AUTH_TYPE_USB,
    };
    struct k1_auth_map_value *elem = k1_bpf_auth_map_lookup(&key);

    if(!elem)
        return 0;

    k1_change_user_auth_state(
        &elem->verdict_entry_lookup_info, key.uid, K1_FLAG_CHANGE_SET);

    elem->is_authenticated = 0;

    return 0;
}

char __license[] SEC("license") = "GPL";
