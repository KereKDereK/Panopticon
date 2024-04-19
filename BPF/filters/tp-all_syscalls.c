#include <linux/if_link.h>
#include <err.h>
#include <unistd.h>
#include "tp-all_syscalls.skel.h"
#define MAX_STACK_RAWTP 100

unsigned int target_pid = 2723;
unsigned int key = 1;
unsigned int syscalls_blacklist[456] = {0};

struct event{
    __u32 pid;
    long syscall_number;
    int user_stack_size;
	int user_stack_buildid_size;
    __u64 user_stack[MAX_STACK_RAWTP];
	struct bpf_stack_build_id user_stack_buildid[MAX_STACK_RAWTP];
    __u64 timestamp;
    bool is_not_good;
};

static int event_logger(void* ctx, void* data, size_t len){
    struct event* evt = (struct event*)data;
    if(evt->pid == getpid())
        return 1;
    printf("%ld\n", evt->user_stack[0]);
    return 0;
}


int main(int argc, char **argv)
{
    syscalls_blacklist[0] = 1;
    syscalls_blacklist[1] = 1;
    struct tp_all_syscalls_bpf *obj;

    obj = tp_all_syscalls_bpf__open_and_load();
    if (!obj)
        err(1, "failed to open and/or load BPF object\n");

    int rbFd = bpf_object__find_map_fd_by_name(obj->obj, "_tp_syscalls_ringbuf");
    struct ring_buffer* ringBuffer = ring_buffer__new(rbFd, event_logger, NULL, NULL);
    if(!ringBuffer){
        printf("Ring buffer failed.\n");
        return 1;
    }
    struct bpf_map* var_map_ptr = bpf_object__find_map_by_name(obj->obj, "_tp_pid_var");
    bpf_map__update_elem(var_map_ptr, &key, sizeof(unsigned int), &target_pid, sizeof(unsigned int), BPF_ANY);

    struct bpf_map* bl_map_ptr = bpf_object__find_map_by_name(obj->obj, "_tp_syscall_bl");
    for (long i = 0; i < 456; ++i){
        bpf_map__update_elem(bl_map_ptr, &i, sizeof(long), &syscalls_blacklist[i], sizeof(unsigned int), BPF_ANY);
    }

    tp_all_syscalls_bpf__attach(obj);
    while(1){
       ring_buffer__consume(ringBuffer);
       sleep(1);
    }
cleanup:
    tp_all_syscalls_pf__destroy(obj);
}