#pragma once
#include "vmlinux.h"
#include "stdio.h"

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

int pin_map(struct bpf_map *map, const char* path);