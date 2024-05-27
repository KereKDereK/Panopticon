#!/bin/bash

sudo ip netns add panopticon;
sudo ip link add veth0 type veth peer name veth1;
sudo ip link set veth0 netns panopticon;
sudo ip netns exec panopticon ifconfig veth0 up 192.168.10.1 netmask 255.255.255.0;
sudo ifconfig veth1 up 192.168.10.254 netmask 255.255.255.0;
sudo ip netns exec panopticon route add default gw 192.168.10.254 dev veth0;
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';
#sudo iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o ens33 -j SNAT --to-source 192.168.109.154;
sudo ip netns exec panopticon ip a;
ip netns exec panopticon ip link set dev lo up;
sudo iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o ens33 -j MASQUERADE;
iptables -A FORWARD -i ens33 -o veth1 -j ACCEPT
iptables -A FORWARD -o ens33 -i veth1 -j ACCEPT
#sudo alias Panopticon_test="sudo ip netns exec panopticon ./panopticon_launch.sh";
#sudo alias Panopticon_agregate="./agregate.py";

