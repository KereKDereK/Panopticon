#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int simple(void *ctx)
{
        return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
