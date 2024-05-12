#!/bin/bash

clang -O2 -g -c -target bpf -I ../../libbpf/src/root/usr/include $1-$2.bpf.c -o $1-$2.bpf.o;
bpftool gen skeleton $1-$2.bpf.o > $1-$2.skel.h;
clang -O2 -g -I ../../libbpf/src/root/usr/include/ -o $1-$2 $1-$2.c ../../libbpf/src/root/usr/lib64/libbpf.a ../blazesym/target/debug/libblazesym.a -lelf -lz -lrt -ldl -lpthread -lm;
