#!/bin/bash

echo "Pcap statistics:"
tshark -r "$1" -q -z io,phs;
tshark -r "$1" -q -z endpoints,ip;