#!/bin/bash
mount -t bpf bpf /sys/fs/bpf;
df /sys/fs/bpf;
mkdir /etc/netns/panopticon;
sysctl -w net.ipv4.ip_forward=1;
sysctl --system;
resolvconf -u;
perf list tracepoint;
sudo ../filters/Panopticon $1 $2;
rm -f ./callgrind_out.txt;
