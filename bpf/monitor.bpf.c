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
    struct iphdr ip;
    struct {
        __be16 source;
        __be16 dest;
    } ports = {};

    if (bpf_ntohs(skb->protocol) != ETH_P_IP)
        return TC_ACT_OK;

    if (bpf_skb_load_bytes_relative(skb, 0, &ip, sizeof(ip), BPF_HDR_START_NET) < 0)
        return TC_ACT_OK;

    if (ip.version != 4)
        return TC_ACT_OK;

    __u32 ip_hdr_len = (__u32)ip.ihl * 4;
    if (ip_hdr_len < sizeof(ip))
        return TC_ACT_OK;

    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
        if (bpf_skb_load_bytes_relative(skb, ip_hdr_len, &ports, sizeof(ports), BPF_HDR_START_NET) < 0)
            return TC_ACT_OK;
    }

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return TC_ACT_OK;  /* ring full -- drop event, not packet */

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = ip.saddr;
    evt->dst_ip       = ip.daddr;
    evt->src_port     = ports.source;
    evt->dst_port     = ports.dest;
    evt->pkt_len      = skb->len;
    evt->protocol     = ip.protocol;
    evt->direction    = dir;

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
