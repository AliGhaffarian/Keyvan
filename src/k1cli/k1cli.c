#include <bpf/libbpf.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <verdict.h>

#include <auth_record.h>
#include <bpf_progs.skel.h>

#include "opt.h"


int main(int argc, char **argv){
    handle_args(argc, argv);

    struct bpf_progs *skel;
    skel = bpf_progs__open_and_load();
    if(!skel){
        printf("%s\n", strerror(errno));
        return 1;
    }

    init_maps_based_on_args(skel);

    bpf_progs__attach(skel);
    while(1){

    }
}
