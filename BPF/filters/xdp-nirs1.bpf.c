#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

typedef struct dip_proto_dport {
        u32 dst_ip;
        u16 dst_port;
        u8 ip_proto;
} _dip_proto_dport;

typedef struct tsmp_sip_sport {
        u64 timestamp;
        u32 src_ip;
        u16 src_port;
} _tsmp_sip_sport;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192); //subject to change
    __type(key, _dip_proto_dport);
    __type(value, _tsmp_sip_sport);
} _nir1_map SEC(".maps");

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
        return XDP_DROP;
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
        return XDP_DROP;
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
            return XDP_DROP;
        }

        if (tcph + 1 > (struct tcphdr *)data_end){
            bpf_printk("[!] Error, no tcp header\n");
            return XDP_DROP;
        }

        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = htonl(iph->daddr);
        key.ip_proto = iph->protocol;
        key.dst_port = htons(tcph->dest);

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = htonl(iph->saddr);
        new_value.src_port = htons(tcph->source);

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else if (iph->protocol == 17)
    {
        struct udphdr *udph = {0};
        if (iph)
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_DROP;
        
        if (udph + 1 > (struct udphdr *)data_end){
            bpf_printk("[!] Error, no udp header\n");
            return XDP_DROP;
        }
        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = htonl(iph->daddr);
        key.ip_proto = iph->protocol;
        key.dst_port = htons(udph->dest);

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = htonl(iph->saddr);
        new_value.src_port = htons(udph->source);

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else if (iph->protocol == 132){
        struct sctphdr *sctph = {0};
        if (iph)
            sctph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
        else
            return XDP_DROP;
        
        if (sctph + 1 > (struct sctphdr *)data_end){
            bpf_printk("[!] Error, no sctph header\n");
            return XDP_DROP;
        }
        struct dip_proto_dport key = {0};
        struct tsmp_sip_sport new_value = {0};

        key.dst_ip = htonl(iph->daddr);
        key.ip_proto = iph->protocol;
        key.dst_port = htons(sctph->dest);

        new_value.timestamp = bpf_ktime_get_boot_ns();
        new_value.src_ip = htonl(iph->saddr);
        new_value.src_port = htons(sctph->source);

        bpf_map_update_elem(&_nir1_map, &key, &new_value, BPF_ANY);

        return XDP_PASS;
    }
    else{
        bpf_printk("[!] Error, unknown proto\n");
        return XDP_DROP;
    }
    bpf_printk("[!] Func end\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";