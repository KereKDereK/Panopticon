#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#define MAX_STACK_RAWTP 100


struct event{
    u32 pid;
    long syscall_number;
    int user_stack_size;
	int user_stack_buildid_size;
    __u64 user_stack[MAX_STACK_RAWTP];
	struct bpf_stack_build_id user_stack_buildid[MAX_STACK_RAWTP];
    u64 timestamp;
    bool is_not_good;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1); //subject to change
    __type(key, u32);
    __type(value, u32);
} _tp_pid_var SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 456); //subject to change
    __type(key, long);
    __type(value, u32);
} _tp_syscall_bl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} _tp_syscalls_ringbuf SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int tp_all_syscalls(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    u32 *target_pid;
    u32 key = 1;
    if (!&_tp_pid_var){
        return 0;
    }
    target_pid = bpf_map_lookup_elem(&_tp_pid_var, &key);

    if(!target_pid){
        bpf_printk("No pid specified. Abort.");
        return 1;
    }

    if (pid != *target_pid){
        return 0;
    }
    int max_len, max_buildid_len;
    struct event* evt = bpf_ringbuf_reserve(&_tp_syscalls_ringbuf, sizeof(struct event), 0);
    if (!evt) {
        bpf_printk("Can't reserve");
        return 1;
    }
    max_len = MAX_STACK_RAWTP * sizeof(__u64);
    max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);

    evt->user_stack_size = bpf_get_stack(ctx, evt->user_stack, max_len,
					    BPF_F_USER_STACK);
	evt->user_stack_buildid_size = bpf_get_stack(
		ctx, evt->user_stack_buildid, max_buildid_len,
		BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
    long syscall_id = 0;
    syscall_id = ctx->id;
    evt->syscall_number = syscall_id;
    evt->timestamp = bpf_ktime_get_boot_ns();


    if (!&_tp_syscall_bl){
        bpf_printk("No blacklist map specified. Abort.");
        evt->is_not_good = false;
        bpf_ringbuf_submit(evt, 0);
        return 1;
    }
    
    u32 *is_not_good;
    is_not_good = bpf_map_lookup_elem(&_tp_syscall_bl, &syscall_id);

    if(!is_not_good){
        evt->is_not_good = false;
        bpf_ringbuf_submit(evt, 0);
        return 1;
    }
    evt->is_not_good = *is_not_good;
    bpf_ringbuf_submit(evt, 0);

    if(*is_not_good != 0){
        return 0;
    }
    
    bpf_printk("Bad syscall! SIGKILL");
    //bpf_send_signal(9);
    return 0;
}
char _license[] SEC("license") = "GPL";