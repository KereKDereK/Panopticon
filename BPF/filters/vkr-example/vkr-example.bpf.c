#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int example_prog(void *ctx)
{
    bpf_printk("[!] Network activity registered!\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";