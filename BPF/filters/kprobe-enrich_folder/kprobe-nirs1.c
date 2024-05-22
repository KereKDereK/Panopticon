#include <linux/if_link.h>
#include <err.h>
#include <unistd.h>
#include "kprobe-nirs1.skel.h"

int main(int argc, char **argv)
{
    struct kprobe_nirs1_bpf *obj;

    obj = kprobe_nirs1_bpf__open_and_load();
    if (!obj)
        err(1, "failed to open and/or load BPF object\n");
    
     kprobe_nirs1_bpf__attach(obj);
cleanup:
    kprobe_nirs1_bpf__destroy(obj);
}