#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event{
    u32 pid;
    long unsigned int syscall_number;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); //subject to change
    __type(key, u16);
    __type(value, u32);
} _kprobe_nir1_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} _kprobe_nir1_ringbuf SEC(".maps");

SEC("kprobe/security_socket_connect")
int kprobe_nirs1(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    long unsigned int syscall_id = 0;
    syscall_id = ctx->ax;
    pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&_kprobe_nir1_map, &pid, &syscall_id, BPF_ANY);

    struct event* evt = bpf_ringbuf_reserve(&_kprobe_nir1_ringbuf, sizeof(struct event), 0);
    if (!evt) {
        bpf_printk("Can't reserve");
        return 1;
    }
    evt->pid = pid;
    evt->syscall_number = syscall_id;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
char _license[] SEC("license") = "GPL";