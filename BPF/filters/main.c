#include <linux/if_link.h>
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/wait.h>
#include <signal.h> 
#include <sys/types.h>
#include "tp-all_syscalls_folder/tp-all_syscalls.skel.h"
#include "tp-stacktrace_folder/tp-stacktrace.skel.h"
#include "xdp-filter_folder/xdp-nirs1.skel.h"
#include "kprobe-enrich_folder/kprobe-nirs1.skel.h"
#include "../blazesym/target/debug/blazesym.h"
#include <bits/getopt_core.h>
#include "sqlite3.h"
#include "time.h"

sqlite3 *db;

bool breaking = false;

/*  MISC  */
char* current_stacktrace;
struct ring_buffer *ring_buf = NULL;
struct ring_buffer* xdp_ring_buf = NULL;
int session = 0;

struct xdp_event{
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 ip_proto;
    __u64 timestamp;
};

#define SEC_TO_NS(sec) ((sec)*1000000000)

__u64 bpf_timestamp_to_epoch_ns(__u64 timestamp){
    struct timespec tms_mono;
    struct timespec tms_real;

    if (clock_gettime(1, &tms_mono)) {
        return -1;
    }
    if (clock_gettime(0, &tms_real)) {
        return -1;
    }

    __u64 real_timestamp = SEC_TO_NS(tms_real.tv_sec) + tms_real.tv_nsec;
    __u64 mono_timestamp = SEC_TO_NS(tms_mono.tv_sec) + tms_mono.tv_nsec;
    __u64 timestamp_without_boot = real_timestamp - mono_timestamp;

    return timestamp_without_boot + timestamp;
}

/*  DB  */

int create_db(){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    const char sql1[] = "CREATE TABLE IF NOT EXISTS SESSIONS("  
                        "SESSION_ID INT PRIMARY KEY,"
                        "BINARY_NAME TEXT NOT NULL,"
                        "SESSION_START INT NOT NULL);";
    rc = sqlite3_exec(db, sql1, NULL, NULL, NULL);

    const char sql2[] = "CREATE TABLE IF NOT EXISTS SYSCALL_EVENTS("  
                        "EVENT_ID INT PRIMARY KEY,"
                        "SESSION_ID INT NOT NULL,"
                        "SYSCALL_ID INT NOT NULL,"
                        "SYSCALL_TIMESTAMP INT NOT NULL,"
                        "SYSCALL_STACKTRACE TEXT NOT NULL);";
    rc = sqlite3_exec(db, sql2, NULL, NULL, NULL);

    const char sql3[] = "CREATE TABLE IF NOT EXISTS NETWORK_EVENTS("  
                        "NETWORK_EVENT_ID INT PRIMARY KEY,"
                        "SESSION_ID INT NOT NULL,"
                        "IP_PROTO INT NOT NULL,"
                        "DST_IP TEXT NOT NULL,"
                        "DST_PORT INT NOT NULL,"
                        "SRC_IP TEXT NOT NULL,"
                        "SRC_PORT INT NOT NULL,"
                        "EVENT_TIMESTAMP INT NOT NULL);";
    rc = sqlite3_exec(db, sql3, NULL, NULL, NULL);

    const char sql4[] = "CREATE TABLE IF NOT EXISTS CALLGRIND_EVENTS("  
                        "CALLGRIND_EVENT_ID INT PRIMARY KEY,"
                        "SESSION_ID INT NOT NULL,"
						"SYMBOL_NAME TEXT NOT NULL,"
                        "EVENT_TIMESTAMP INT NOT NULL);";
    rc = sqlite3_exec(db, sql4, NULL, NULL, NULL);

    sqlite3_close(db);
    return 0;
}

int insert_session(int id, char* binary_name, struct timespec tms){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "INSERT INTO SESSIONS (SESSION_ID, BINARY_NAME, SESSION_START) " 
                    "VALUES (%d,\"%s\", %llu%llu);", id, binary_name, tms.tv_sec, tms.tv_nsec);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;          
}

int insert_callgrind(int session_id, char* symbol_name,__u64 timestamp){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "INSERT INTO CALLGRIND_EVENTS (SESSION_ID, SYMBOL_NAME, EVENT_TIMESTAMP) " 
                    "VALUES (%d, \"%s\",%llu);", session_id, symbol_name, timestamp);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;   
}

int insert_syscall(int session_id, long syscall_id, __u64 timestamp, char* stack_trace){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[10000];
    sprintf(buffer, "INSERT INTO SYSCALL_EVENTS (SESSION_ID, SYSCALL_ID, SYSCALL_TIMESTAMP, SYSCALL_STACKTRACE) " 
                    "VALUES (%d, %ld, %lld, \"%s\");", session_id, syscall_id, timestamp, stack_trace);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;    
}

char* ip_to_str(__u32 src_ip_addr){
	char* buffer = (char*)calloc(1000, sizeof(char));

	unsigned char bytes[4];
    bytes[0] = src_ip_addr & 0xFF;
    bytes[1] = (src_ip_addr >> 8) & 0xFF;
    bytes[2] = (src_ip_addr >> 16) & 0xFF;
    bytes[3] = (src_ip_addr >> 24) & 0xFF; 

	sprintf(buffer, "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
	return buffer;
}

int insert_network(int session_id, __u8 ip_proto, __u32 dst_ip, __u32 dst_port, __u32 src_ip, __u32 src_port, __u64 timestamp){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);
	char source[20] = {0};
	char dest[20] = {0};

	unsigned char bytes[4];
    bytes[0] = src_ip & 0xFF;
    bytes[1] = (src_ip >> 8) & 0xFF;
    bytes[2] = (src_ip >> 16) & 0xFF;
    bytes[3] = (src_ip >> 24) & 0xFF;
	sprintf(source, "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);

    bytes[0] = dst_ip & 0xFF;
    bytes[1] = (dst_ip >> 8) & 0xFF;
    bytes[2] = (dst_ip >> 16) & 0xFF;
    bytes[3] = (dst_ip >> 24) & 0xFF;
	sprintf(dest, "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);

    char buffer[5000];
    sprintf(buffer, "INSERT INTO NETWORK_EVENTS (SESSION_ID, IP_PROTO, DST_IP, DST_PORT, SRC_IP, SRC_PORT, EVENT_TIMESTAMP) " 
                    "VALUES (%d, %hu, \"%s\", %d, \"%s\", %d, %llu);", session_id, ip_proto, dest, dst_port, 
                                                                       source, src_port, timestamp);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;    
}

int get_max_session_id() {
    unsigned int max_id = 0;
    int rc; 
    sqlite3_stmt *res;
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "SELECT (max(SESSION_ID)) FROM SESSIONS LIMIT 1;");

    rc = sqlite3_prepare_v2( db, buffer, -1, &res, 0 );

    while( sqlite3_step(res) == SQLITE_ROW )
    {
        max_id = sqlite3_column_int(res, 0);
    }
    sqlite3_finalize(res);
    sqlite3_close(db);

    return max_id;
}

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

#define MAX_STACK_RAWTP 100
pid_t target_pid = 0;
unsigned int key = 1;
unsigned int syscalls_blacklist[456] = {0};

struct event{
    __u32 pid;
    long syscall_number;
    __u64 timestamp;
    bool is_not_good;
};

int event_logger_syscalls(void* ctx, void* data, size_t len){
	int status;
	// if (waitpid(target_pid, &status, WNOHANG) > 0){
	// 	return -1;
	// }
	// else {
	// 	printf("Nothing\n");
	// }
	printf("Syscall\n");
    struct event* evt = (struct event*)data;
	ring_buffer__poll(ring_buf, -1);
	ring_buffer__poll(xdp_ring_buf, -1);

    if(evt->pid == getpid())
        return 1;
    //printf("%d:%ld:%lld\n", evt->pid, evt->syscall_number, evt->timestamp);
	//printf("Timestamp: %llu\n", bpf_timestamp_to_epoch_ns(evt->timestamp));
	insert_syscall(session, evt->syscall_number, bpf_timestamp_to_epoch_ns(evt->timestamp), current_stacktrace);
    return 0;
}

/*  TP STACKTRACE  */

extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static struct blazesym *symbolizer;

void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blazesym_result *result;
	const struct blazesym_csym *sym;
	sym_src_cfg src;
	int i, j;
    int offset = 0;

	if (pid) {
		src.src_type = SRC_T_PROCESS;
		src.params.process.pid = pid;
	} else {
		src.src_type = SRC_T_KERNEL;
		src.params.kernel.kallsyms = NULL;
		src.params.kernel.kernel_image = NULL;
	}

	result = blazesym_symbolize(symbolizer, &src, 1, (const uint64_t *)stack, stack_sz);

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->size <= i || !result->entries[i].size) {
			// printf("  %d [<%016llx>]\n", i, stack[i]);
            offset += sprintf(current_stacktrace + offset, "  %d [<%016llx>]\n", i, stack[i]);

			continue;
		}

		if (result->entries[i].size == 1) {
			sym = &result->entries[i].syms[0];
			if (sym->path && sym->path[0]) {
				// printf("  %d [<%016llx>] %s+0x%llx %s:%ld\ttsp: \n",
				//        i, stack[i], sym->symbol,
				//        stack[i] - sym->start_address,
				//        sym->path, sym->line_no);

                offset += sprintf(current_stacktrace + offset, "  %d [<%016llx>] %s+0x%llx %s:%ld\ttsp: \n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address,
				       sym->path, sym->line_no);
                       
			} else {
				// printf("  %d [<%016llx>] %s+0x%llx\n",
				//        i, stack[i], sym->symbol,
				//        stack[i] - sym->start_address);
                offset += sprintf(current_stacktrace + offset, "  %d [<%016llx>] %s+0x%llx\n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address);
			}
			continue;
		}

		// printf("  %d [<%016llx>]\n", i, stack[i]);

        offset += sprintf(current_stacktrace + offset, "  %d [<%016llx>]\n", i, stack[i]);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			if (sym->path && sym->path[0]) {
				// printf("        %s+0x%llx %s:%ld\n",
				//        sym->symbol, stack[i] - sym->start_address,
				//        sym->path, sym->line_no);
                offset += sprintf(current_stacktrace + offset, "        %s+0x%llx %s:%ld\n",
				       sym->symbol, stack[i] - sym->start_address,
				       sym->path, sym->line_no);
			} else {
				// printf("        %s+0x%llx\n", sym->symbol,
				//        stack[i] - sym->start_address);
                offset += sprintf(current_stacktrace + offset, "        %s+0x%llx\n", sym->symbol,
				       stack[i] - sym->start_address);
			}
		}
	}

	current_stacktrace[offset + 1] = "\0";
	//printf("%s\n", current_stacktrace);
	blazesym_result_free(result);
}

static int stacktrace_event_handler(void *_ctx, void *data, size_t size) {
	struct stacktrace_event *event = data;

    if(event->pid != target_pid)
        return 1;

	if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
		return 1;

	//printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

	// if (event->kstack_sz > 0) {
	// 	printf("Timestamp: %lld\tKernel:\n", event->timestamp);
	// 	show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
	// } else {
	// 	printf("No Kernel Stack\n");
	// }

	if (event->ustack_sz > 0) {
		//printf("Userspace:\n");
		show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
	}

	return 0;
}

int parse_callgrind_out() { 
	FILE *fp;
    char *line = NULL;
	char *token = NULL;
	bool flag = false;
    size_t len = 0;
    ssize_t read;

	char* name = NULL;
	char* end = NULL;
	__u64 timestamp;

    fp = fopen("./callgrind_out.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
		while ((token = strsep(&line, "|"))) {
			if(!flag){
				name = token;
				flag = true;
			}
			else {
				timestamp = strtoull(token, &end, 10);
				flag = false;
			}
		}
        insert_callgrind(session, name, timestamp);
    }

    fclose(fp);
    if (line)
        free(line);
}

int event_logger_network(void* ctx, void* data, size_t len) {
	struct xdp_event* evt = data;
	insert_network(session, evt->ip_proto, evt->dst_ip, evt->dst_port, evt->src_ip, evt->src_port, bpf_timestamp_to_epoch_ns(evt->timestamp));
	return 1;
}

// int handle_sigint() {
// 	kill(target_pid, 9);
// 	return 1;
// }

int main(int argc, char **argv)
{
	//signal(SIGINT, handle_sigint); 
    if (argc < 2)
        return 0;
	system("touch ./callgrind_out.txt");
	char* path_to_binary = argv[1];
    target_pid = fork();
	if (target_pid == -1)
		return -1;
	
	if (target_pid == 0){
		execl("../../valgrind_bin/bin/valgrind", " ", "--tool=callgrind", path_to_binary);
	}
    create_db();

	current_stacktrace = (char*)calloc(100000, sizeof(char));
    
    struct timespec tms;

    if (clock_gettime(0,&tms)) {
        return -1;
    }

    session = get_max_session_id() + 1;
    insert_session(session, path_to_binary, tms);

    /*  TP ALL SYSCALLS  */

    syscalls_blacklist[0] = 1;
    syscalls_blacklist[1] = 1;
    struct tp_all_syscalls_bpf *obj;

    obj = tp_all_syscalls_bpf__open_and_load();
    if (!obj)
        printf("failed to open and/or load BPF object\n");

    int rbFd = bpf_object__find_map_fd_by_name(obj->obj, "_tp_syscalls_ringbuf");
    struct ring_buffer* ringBuffer = ring_buffer__new(rbFd, event_logger_syscalls, NULL, NULL);
    if(!ringBuffer){
        printf("Ring buffer failed.\n");
        return 1;
    }
    struct bpf_map* var_map_ptr = bpf_object__find_map_by_name(obj->obj, "_pid_var");
	if(target_pid)
    	bpf_map__update_elem(var_map_ptr, &key, sizeof(unsigned int), (unsigned int)&target_pid, sizeof(unsigned int), BPF_ANY);

    struct bpf_map* bl_map_ptr = bpf_object__find_map_by_name(obj->obj, "_tp_syscall_bl");
    for (long i = 0; i < 456; ++i){
        bpf_map__update_elem(bl_map_ptr, &i, sizeof(long), &syscalls_blacklist[i], sizeof(unsigned int), BPF_ANY);
    }

    tp_all_syscalls_bpf__attach(obj);


    /*  TP STACKTRACE  */

    const char *online_cpus_file = "/sys/devices/system/cpu/online";
	int freq = 1, pid = -1, cpu;
	struct tp_stacktrace_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;

	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp =0;
    int i = 0;
    int err = 0;
	bool *online_mask = NULL;

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	skel = tp_stacktrace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	symbolizer = blazesym_new();
	if (!symbolizer) {
		fprintf(stderr, "Fail to create a symbolizer\n");
		err = -1;
		goto cleanup;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), stacktrace_event_handler, NULL, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = freq;
	attr.freq = 1;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* Set up performance monitoring on a CPU/Core */
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	struct kprobe_nirs1_bpf *obj_kprobe;

    obj_kprobe = kprobe_nirs1_bpf__open_and_load();
    if (!obj_kprobe)
        printf("failed to open and/or load BPF object\n");
    
     kprobe_nirs1_bpf__attach(obj_kprobe);


	/*  XDP-FILTER  */

	__u32 flags = XDP_FLAGS_SKB_MODE;
    struct xdp_nirs1_bpf *obj_xdp;

    obj_xdp = xdp_nirs1_bpf__open_and_load();
    if (!obj_xdp)
        printf("failed to open and/or load BPF object\n");

    bpf_xdp_attach(2, -1, flags, NULL);
    bpf_xdp_attach(2, bpf_program__fd(obj_xdp->progs.nirs1), flags, NULL);

	int xdp_fd = bpf_object__find_map_fd_by_name(obj_xdp->obj, "_xdp_event_ringbuf");
    xdp_ring_buf = ring_buffer__new(xdp_fd, event_logger_network, NULL, NULL);
    if(!ringBuffer){
        printf("Ring buffer failed.\n");
        return 1;
    }

	int status;
    while(!breaking){
		printf("SOMETHING, %d\n", target_pid);
    	int err = ring_buffer__poll(ringBuffer, 100);
		sleep(1);
		if (waitpid(target_pid, &status, WNOHANG) > 0)
			breaking = true;
    }

cleanup:
	parse_callgrind_out();

    tp_all_syscalls_bpf__destroy(obj);
	kprobe_nirs1_bpf__destroy(obj_kprobe);
	xdp_nirs1_bpf__destroy(obj_xdp);
    if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	ring_buffer__free(ring_buf);
	tp_stacktrace_bpf__destroy(skel);
	blazesym_free(symbolizer);
	free(online_mask);
	return -err;
}
