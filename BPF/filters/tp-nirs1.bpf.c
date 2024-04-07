#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct event{
    u32 pid;
    long syscall_number;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); //subject to change
    __type(key, u32);
    __type(value, long);
} _tp_nir1_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} _tp_nir1_ringbuf SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int tp_nirs1(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    long syscall_id = 0;
    syscall_id = ctx->id;
    pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&_tp_nir1_map, &pid, &syscall_id, BPF_ANY);

    struct event* evt = bpf_ringbuf_reserve(&_tp_nir1_ringbuf, sizeof(struct event), 0);
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