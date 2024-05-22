#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192*8); //subject to change
    __type(key, u16);
    __type(value, u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _xdp_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1); //subject to change
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _pid_var SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, s32);
        __type(value, struct sock *);
        __uint(max_entries, 1000);
} currsock SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int tcpconn_entry(struct pt_regs *ctx) { 
    struct sock *sk = (struct sock *)ctx->di; 
    s32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&currsock, &pid, &sk, BPF_ANY);
    return 0;
};

SEC("kretprobe/tcp_v4_connect")
int tcpconn_return(struct pt_regs *ctx) { 
    long ret = ctx->ax;
    u8 *idxvaluePtr;
    u8 idxvalue;
    u32 idxvalue32;
    u32 index = 0;
    struct task_struct *task;
    struct task_struct *real_parent;
	struct sock **skpp;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 1;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 port;

    u32 *target_pid;
    u32 key = 1;
    u8 value = 1;
    if (!&_pid_var){
        return 0;
    }
    target_pid = bpf_map_lookup_elem(&_pid_var, &key);

    if(!target_pid){
        //bpf_printk("No pid specified. Abort.");
        return 1;
    }

    if (pid != *target_pid){
        return 0;
    }

    skpp = bpf_map_lookup_elem(&currsock, &pid);
	if (skpp == 0) {
		return 0; //sock not found
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		bpf_map_delete_elem(&currsock, &pid);
		return 0;
	}

    struct sock *skp = *skpp;
    bpf_probe_read(&port, sizeof(u16), &skp->__sk_common.skc_num);

    bpf_map_update_elem(&_xdp_port_map, &port, &value, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";