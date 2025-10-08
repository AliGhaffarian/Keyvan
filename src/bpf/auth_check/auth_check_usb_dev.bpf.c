#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <k1_limits.h>
#include <k1_map.h>
#include <k1_bpf_util.h>

struct k1_auth_map_hash __attribute__((weak)) auth_map_hash SEC(".maps");
struct k1_verdict_map_hash __attribute__((weak)) verdict_map_hash SEC(".maps");

static const enum K1_AUTH_TYPE const_auth_type_usb = K1_AUTH_TYPE_USB;

SEC("fentry/usb_create_sysfs_dev_files")
int BPF_PROG(auth_check_usb_create_sysfs, struct usb_device *udev){
    if(!udev->serial)
        return 0;

    bpf_printk("connected udev: %s", udev->serial);

    struct k1_record_list *elem = bpf_map_lookup_elem(&auth_map_hash, &const_auth_type_usb);
    if(!elem)
        return 0;


    for(int i = 0; i < elem->len && i < K1_MAX_USER_RECORDS; i++){

        // we already looked up the records with the key `K1_AUTH_TYPE_USB`. don't check for it again

        if (elem->records[i].is_authenticated)
            continue;

        if (k1_strcmp(udev->serial, elem->records[i].auth_check_detail.auth_usb.serial))
            continue;

        k1_change_user_auth_state(
                elem->records[i].verdict_hook,
                elem->records[i].uid,
                K1_FLAG_CHANGE_SET
                );
        elem->records[i].is_authenticated = 1;
    }

    return 0;
}

SEC("fentry/usb_remove_sysfs_dev_files")
int BPF_PROG(auth_check_usb_remove_sysfs, struct usb_device *udev){

    if(!udev->serial)
        return 0;

    bpf_printk("disconnected udev: %s", udev->serial);

    struct k1_record_list *elem = bpf_map_lookup_elem(&auth_map_hash, &const_auth_type_usb);
    if(!elem)
        return 0;


    for(int i = 0; i < elem->len && i < K1_MAX_USER_RECORDS; i++){
        if (K1_AUTH_TYPE_USB != elem->records[i].auth_check_detail.auth_type)
            continue;

        if (!elem->records[i].is_authenticated)
            continue;

        if (k1_strcmp(udev->serial, elem->records[i].auth_check_detail.auth_usb.serial))
            return 0;

        k1_change_user_auth_state(
                elem->records[i].verdict_hook,
                elem->records[i].uid,
                K1_FLAG_CHANGE_CLEAR 
                );
        elem->records[i].is_authenticated = 0;
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
