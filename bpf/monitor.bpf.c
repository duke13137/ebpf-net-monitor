/**
 * eBPF TC classifier program for network packet monitoring.
 *
 * Attaches to both ingress and egress TC hooks. For each IPv4 packet,
 * extracts (src_ip, dst_ip, protocol, pkt_len) and writes a net_event
 * to a BPF ring buffer for userspace consumption.
 *
 * Requires: Linux 6.1+, CONFIG_DEBUG_INFO_BTF=y, clang/llvm for BPF target.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../cbits/monitor.h"

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  /* 1 MB ring buffer */
} events SEC(".maps");

static __always_inline int handle_packet(struct __sk_buff *skb, __u8 dir) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Ethernet header bounds check (verifier requirement) */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* IP header bounds check (verifier requirement) */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return TC_ACT_OK;  /* ring full -- drop event, not packet */

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = ip->saddr;
    evt->dst_ip       = ip->daddr;
    evt->pkt_len      = skb->len;
    evt->protocol     = ip->protocol;
    evt->direction    = dir;
    evt->_pad[0]      = 0;
    evt->_pad[1]      = 0;

    bpf_ringbuf_submit(evt, 0);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int monitor_ingress(struct __sk_buff *skb) {
    return handle_packet(skb, DIR_INGRESS);
}

SEC("tc/egress")
int monitor_egress(struct __sk_buff *skb) {
    return handle_packet(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
