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
#include "tp-all_syscalls_folder/tp-all_syscalls.skel.h"
#include "tp-stacktrace_folder/tp-stacktrace.skel.h"
#include "../blazesym/target/debug/blazesym.h"
#include <bits/getopt_core.h>
#include "sqlite3.h"
#include "time.h"

sqlite3 *db;

/*  MISC  */

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

int insert_callgrind(int session_id, __u64 timestamp){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "INSERT INTO CALLGRIND_EVENTS (SESSION_ID, EVENT_TIMESTAMP) " 
                    "VALUES (%d, %llu);", session_id, timestamp);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;   
}

int insert_syscall(int session_id, long syscall_id, __u64 timestamp, char* stack_trace){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "INSERT INTO SYSCALL_EVENTS (SESSION_ID, SYSCALL_ID, SYSCALL_TIMESTAMP, SYSCALL_STACKTRACE) " 
                    "VALUES (%d, %ld, %lld, \"%s\");", session_id, syscall_id, timestamp, stack_trace);
    rc = sqlite3_exec(db, buffer, NULL, NULL, NULL);
    sqlite3_close(db);
    return 0;    
}

int insert_network(int session_id, __u8 ip_proto, __u32 dst_ip, __u32 dst_port, __u32 src_ip, __u32 src_port, __u64 timestamp){
    int rc; 
    rc = sqlite3_open("panopticon.db", &db);

    char buffer[1000];
    sprintf(buffer, "INSERT INTO NETWORK_EVENTS (SESSION_ID, IP_PROTO, DST_IP, DST_PORT, SRC_IP, SRC_PORT, EVENT_TIMESTAMP) " 
                    "VALUES (%d, %hu, \"%s\", %d, \"%s\", %d, %llu);", session_id, ip_proto, inet_ntoa(htonl(dst_ip)), dst_port, 
                                                                       inet_ntoa(htonl(src_ip)), src_port, timestamp);
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
unsigned int target_pid = 0;
unsigned int key = 1;
unsigned int syscalls_blacklist[456] = {0};

struct event{
    __u32 pid;
    long syscall_number;
    __u64 timestamp;
    bool is_not_good;
};

static int event_logger_syscalls(void* ctx, void* data, size_t len){
    return 1;
    struct event* evt = (struct event*)data;
    if(evt->pid == getpid())
        return 1;
    printf("%d:%ld:%lld\n", evt->pid, evt->syscall_number, evt->timestamp);
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

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blazesym_result *result;
	const struct blazesym_csym *sym;
	sym_src_cfg src;
	int i, j;
    char final_trace[10000];
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
            offset += sprintf(final_trace + offset, "  %d [<%016llx>]\n", i, stack[i]);

			continue;
		}

		if (result->entries[i].size == 1) {
			sym = &result->entries[i].syms[0];
			if (sym->path && sym->path[0]) {
				// printf("  %d [<%016llx>] %s+0x%llx %s:%ld\ttsp: \n",
				//        i, stack[i], sym->symbol,
				//        stack[i] - sym->start_address,
				//        sym->path, sym->line_no);

                offset += sprintf(final_trace + offset, "  %d [<%016llx>] %s+0x%llx %s:%ld\ttsp: \n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address,
				       sym->path, sym->line_no);
                       
			} else {
				// printf("  %d [<%016llx>] %s+0x%llx\n",
				//        i, stack[i], sym->symbol,
				//        stack[i] - sym->start_address);
                offset += sprintf(final_trace + offset, "  %d [<%016llx>] %s+0x%llx\n",
				       i, stack[i], sym->symbol,
				       stack[i] - sym->start_address);
			}
			continue;
		}

		// printf("  %d [<%016llx>]\n", i, stack[i]);

        offset += sprintf(final_trace + offset, "  %d [<%016llx>]\n", i, stack[i]);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			if (sym->path && sym->path[0]) {
				// printf("        %s+0x%llx %s:%ld\n",
				//        sym->symbol, stack[i] - sym->start_address,
				//        sym->path, sym->line_no);
                offset += sprintf(final_trace + offset, "        %s+0x%llx %s:%ld\n",
				       sym->symbol, stack[i] - sym->start_address,
				       sym->path, sym->line_no);
			} else {
				// printf("        %s+0x%llx\n", sym->symbol,
				//        stack[i] - sym->start_address);
                offset += sprintf(final_trace + offset, "        %s+0x%llx\n", sym->symbol,
				       stack[i] - sym->start_address);
			}
		}
	}

    printf("%s", final_trace);

	blazesym_result_free(result);
}

static int stacktrace_event_handler(void *_ctx, void *data, size_t size)
{
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
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 0;
    target_pid = atoi(argv[1]);
    create_db();
    
    struct timespec tms;

    if (clock_gettime(0,&tms)) {
        return -1;
    }

    int session = get_max_session_id() + 1;
    insert_session(session, "test", tms);


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
    struct bpf_map* var_map_ptr = bpf_object__find_map_by_name(obj->obj, "_tp_pid_var");
    bpf_map__update_elem(var_map_ptr, &key, sizeof(unsigned int), &target_pid, sizeof(unsigned int), BPF_ANY);

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
	struct ring_buffer *ring_buf = NULL;
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

    while(ring_buffer__poll(ring_buf, -1) >= 0 || 1){
       ring_buffer__consume(ringBuffer);
       sleep(1);
    }

cleanup:
    tp_all_syscalls_bpf__destroy(obj);
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
