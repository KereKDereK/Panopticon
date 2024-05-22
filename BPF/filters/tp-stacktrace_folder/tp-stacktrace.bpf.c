#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1); //subject to change
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _pid_var SEC(".maps");

#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH         128
#endif

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event {
	__u32 pid;
	__u32 cpu_id;
	char comm[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
	__u64 timestamp;
};

#endif /* __PROFILE_H_ */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct stacktrace_event *event;
	int cp;

	u32 *target_pid;
    u32 key = 1;
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

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	event->pid = pid;
	event->cpu_id = cpu_id;
	event->timestamp = bpf_ktime_get_boot_ns();

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

	event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(event, 0);

	return 0;
}