#include <linux/if_link.h>
#include <err.h>
#include <unistd.h>
#include "tp-nirs1.skel.h"

struct event{
    int pid;
    long syscall_number;
};

static int event_logger(void* ctx, void* data, size_t len){
    struct event* evt = (struct event*)data;
    if(evt->pid == getpid())
        return 1;
    printf("PID = %d\tSID = %ld\t", evt->pid, evt->syscall_number);
    return 0;
}


int main(int argc, char **argv)
{
    struct tp_nirs1_bpf *obj;

    obj = tp_nirs1_bpf__open_and_load();
    if (!obj)
        err(1, "failed to open and/or load BPF object\n");

    int rbFd = bpf_object__find_map_fd_by_name(obj->obj, "_tp_nir1_ringbuf");
    struct ring_buffer* ringBuffer = ring_buffer__new(rbFd, event_logger, NULL, NULL);
    if(!ringBuffer){
        printf("Ring buffer failed.\n");
        return 1;
    }
    
     tp_nirs1_bpf__attach(obj);
     while(1){
        ring_buffer__consume(ringBuffer);
        sleep(1);
     }
cleanup:
    tp_nirs1_bpf__destroy(obj);
}