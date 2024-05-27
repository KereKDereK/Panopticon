#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} _xdp_event_ringbuf SEC(".maps");

struct event{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u8 ip_proto;
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192*8); //subject to change
    __type(key, u16);
    __type(value, u8);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} _xdp_port_map SEC(".maps");

SEC("xdp")
int nirs1(struct xdp_md *ctx)
{
    if (!ctx)
    {
        bpf_printk("[!] Error, no ctx\n");
        return XDP_PASS;
    }
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

     if (eth + 1 > (struct ethhdr *)data_end)
    {
        bpf_printk("[!] Error, no eth data\n");
        return XDP_PASS;
    }
    uint16_t ethertype;

    if (eth->h_proto != htons(0x0800))
    {
        bpf_printk("[!] Error, no ipv4\n");
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof (struct ethhdr);
    struct ipv6hdr *ipv6_hdr = NULL;


    if (iph + 1 > (struct iphdr *)data_end)
    {
        bpf_printk("[!] Error, no ipheader\n");
        return XDP_PASS;
    }

    //TODO more types (possible switch case and/or helper func)
    if (iph->protocol == 6)
    {
        struct tcphdr *tcph = {0};
        if (iph)
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
        {
            bpf_printk("[!] Error, ipv6\n");
            return XDP_PASS;
        }

        if (tcph + 1 > (struct tcphdr *)data_end){
            bpf_printk("[!] Error, no tcp header\n");
            return XDP_PASS;
        }

        u8 *is_pid;
        u16 key = htons(tcph->dest);
        if (!&_xdp_port_map){
            return XDP_PASS;
        }
        is_pid = bpf_map_lookup_elem(&_xdp_port_map, &key);

        if(!is_pid){
            bpf_printk("No port. Abort. Port: %u", htons(tcph->dest));
            return XDP_PASS;
        }

        if (*is_pid == 0){
            return XDP_PASS;
        }

        struct event* evt = bpf_ringbuf_reserve(&_xdp_event_ringbuf, sizeof(struct event), 0);
        if (!evt) {
            bpf_printk("Can't reserve XDP");
            return 1;
        }

        evt->src_ip = htonl(iph->saddr);
        evt->src_port = htons(tcph->dest);
        evt->dst_ip = htonl(iph->daddr);
        evt->dst_port = htons(tcph->source);
        evt->ip_proto = iph->protocol;
        evt->timestamp = bpf_ktime_get_boot_ns();
        bpf_ringbuf_submit(evt, 0);

        return XDP_DROP;
    }
    else if (iph->protocol == 17)
    {
        struct udphdr *udph = {0};
        if (iph)
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_PASS;
        
        if (udph + 1 > (struct udphdr *)data_end){
            bpf_printk("[!] Error, no udp header\n");
            return XDP_PASS;
        }

        u8 *is_pid;
        u16 key = htons(udph->dest);
        if (!&_xdp_port_map){
            return XDP_PASS;
        }
        is_pid = bpf_map_lookup_elem(&_xdp_port_map, &key);

        if(!is_pid){
            bpf_printk("No port. Abort. Port: %u", htons(udph->dest));
            return XDP_PASS;
        }

        if (*is_pid == 0){
            return XDP_PASS;
        }

        struct event* evt = bpf_ringbuf_reserve(&_xdp_event_ringbuf, sizeof(struct event), 0);
        if (!evt) {
            bpf_printk("Can't reserve XDP");
            return 1;
        }
        
        evt->src_ip = htonl(iph->saddr);
        evt->src_port = htons(udph->dest);
        evt->dst_ip = htonl(iph->daddr);
        evt->dst_port = htons(udph->source);
        evt->ip_proto = iph->protocol;
        evt->timestamp = bpf_ktime_get_boot_ns();
        bpf_ringbuf_submit(evt, 0);

        return XDP_DROP;

    }
    else if (iph->protocol == 132){
        struct sctphdr *sctph = {0};
        if (iph)
            sctph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_PASS;
        
        if (sctph + 1 > (struct sctphdr *)data_end){
            bpf_printk("[!] Error, no sctph header\n");
            return XDP_PASS;
        }

        u8 *is_pid;
        u16 key = htons(sctph->dest);
        if (!&_xdp_port_map){
            return XDP_PASS;
        }
        is_pid = bpf_map_lookup_elem(&_xdp_port_map, &key);

        if(!is_pid){
            bpf_printk("No port. Abort. Port: %u", htons(sctph->dest));
            return XDP_PASS;
        }

        if (*is_pid == 0){
            return XDP_PASS;
        }

        struct event* evt = bpf_ringbuf_reserve(&_xdp_event_ringbuf, sizeof(struct event), 0);
        if (!evt) {
            bpf_printk("Can't reserve XDP");
            return 1;
        }
        
        
        evt->src_ip = htonl(iph->saddr);
        evt->src_port = htons(sctph->dest);
        evt->dst_ip = htonl(iph->daddr);
        evt->dst_port = htons(sctph->source);
        evt->ip_proto = iph->protocol;
        evt->timestamp = bpf_ktime_get_boot_ns();
        bpf_ringbuf_submit(evt, 0);

        return XDP_DROP;

    }
    else{
        bpf_printk("[!] Error, unknown proto\n");
        return XDP_PASS;
    }
    bpf_printk("[!] Func end\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
