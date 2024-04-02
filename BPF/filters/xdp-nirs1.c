#include <linux/if_link.h>
#include <err.h>
#include <unistd.h>
#include "xdp-nirs1.skel.h"

int main(int argc, char **argv)
{
    __u32 flags = XDP_FLAGS_SKB_MODE;
    struct xdp_nirs1_bpf *obj;

    obj = xdp_nirs1_bpf__open_and_load();
    if (!obj)
        err(1, "failed to open and/or load BPF object\n");

    bpf_xdp_attach(1, -1, flags, NULL);
    bpf_xdp_attach(1, bpf_program__fd(obj->progs.nirs1), flags, NULL);

cleanup:
    xdp_nirs1_bpf__destroy(obj);
}