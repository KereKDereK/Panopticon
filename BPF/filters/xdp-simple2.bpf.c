#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int simple(void *ctx)
{
    if (bpf_get_smp_processor_id() != 0)
        return XDP_DROP;
    bpf_printk("running on CPU%u\n", bpf_get_smp_processor_id());
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";