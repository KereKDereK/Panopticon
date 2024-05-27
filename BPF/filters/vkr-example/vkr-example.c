#include <err.h>
#include <unistd.h>
#include "vkr-example.skel.h"
#include <linux/if_link.h>

int main(int argc, char **argv)
{
    struct vkr_example_bpf *obj;

    obj = vkr_example_bpf__open_and_load();
    if (!obj)
        printf("[!] Loading error occured!\n");

    __u32 flags = XDP_FLAGS_SKB_MODE;
    bpf_xdp_attach(1, -1, flags, NULL);
    bpf_xdp_attach(1, bpf_program__fd(obj->progs.example_prog), flags, NULL);

    vkr_example_bpf__destroy(obj);
}