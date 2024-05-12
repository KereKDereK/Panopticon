#!/bin/bash

clang -O2 -g -c -target bpf -I ../../libbpf/src/root/usr/include ./tp-all_syscalls_folder/tp-all_syscalls.bpf.c -o ./tp-all_syscalls_folder/tp-all_syscalls.bpf.o;
bpftool gen skeleton ./tp-all_syscalls_folder/tp-all_syscalls.bpf.o > ./tp-all_syscalls_folder/tp-all_syscalls.skel.h;

clang -O2 -g -c -target bpf -I ../../libbpf/src/root/usr/include ./tp-stacktrace_folder/tp-stacktrace.bpf.c -o ./tp-stacktrace_folder/tp-stacktrace.bpf.o;
bpftool gen skeleton ./tp-stacktrace_folder/tp-stacktrace.bpf.o > ./tp-stacktrace_folder/tp-stacktrace.skel.h;

echo '#pragma once' | cat - ./tp-all_syscalls_folder/tp-all_syscalls.skel.h > temp && mv -f temp ./tp-all_syscalls_folder/tp-all_syscalls.skel.h;
echo '#pragma once' | cat - ./tp-stacktrace_folder/tp-stacktrace.skel.h > temp && mv -f temp ./tp-stacktrace_folder/tp-stacktrace.skel.h;


clang -v -O2 -g -I ../../libbpf/src/root/usr/include -o Panopticon main.c ../../libbpf/src/root/usr/lib64/libbpf.a ../blazesym/target/debug/libblazesym.a -lelf -lz -lrt -ldl -lpthread -lm -lsqlite3;
