/* Isolated ingress/routing/egress feasibility fixture. No product policy/NAT. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 9);
    __type(key, __u32);
    __type(value, __u32);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline __u32 setting(__u32 key)
{
    __u32 *value = bpf_map_lookup_elem(&settings, &key);
    return value ? *value : 0;
}

static __always_inline void add(__u32 key, __u64 amount)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value)
        __sync_fetch_and_add(value, amount);
}

static __always_inline __u16 be16(const unsigned char *p)
{
    return ((__u16)p[0] << 8) | p[1];
}

static __always_inline __u32 identity(const unsigned char *ip)
{
    __u32 hash = 0x6d727531;
#pragma unroll
    for (int i = 12; i < 20; i++)
        hash = (hash * 33) ^ ip[i];
    return hash ^ ((__u32)be16(ip + 4) << 8) ^ ip[9];
}

static __always_inline void clear_receipt(struct __sk_buff *skb)
{
    volatile struct __sk_buff *ctx = skb;
    ctx->cb[0] = 0;
    ctx->cb[1] = 0;
    ctx->cb[2] = 0;
    ctx->cb[3] = 0;
    ctx->cb[4] = 0;
}

static __always_inline void receipt(struct __sk_buff *skb, const unsigned char *ip,
                                   __u32 phase, __u32 binding)
{
    skb->cb[0] = phase;
    skb->cb[1] = setting(4);
    skb->cb[2] = setting(5);
    skb->cb[3] = binding;
    skb->cb[4] = identity(ip) ^ skb->ifindex;
}

static __always_inline int full_udp(struct __sk_buff *skb, unsigned char *ip,
                                  unsigned char *last)
{
    unsigned char udp[8];
    if (bpf_skb_load_bytes(skb, 14, ip, 20) || ip[0] != 0x45 || ip[9] != 17 ||
        (be16(ip + 6) & 0x3fff))
        return 0;
    __u16 total = be16(ip + 2);
    return total >= 28 && skb->len == (__u32)total + 14 &&
        !bpf_skb_load_bytes(skb, 34, udp, 8) && be16(udp + 4) == total - 20 &&
        !bpf_skb_load_bytes(skb, (__u32)total + 13, last, 1);
}

SEC("classifier/ingress")
int ingress(struct __sk_buff *skb)
{
    unsigned char ip[20], last;
    if ((skb->ifindex != setting(1) && skb->ifindex != setting(6)) ||
        !full_udp(skb, ip, &last) || ip[8] != 64) {
        add(5, 1);
        return 0;
    }
    add(9, 1);
    add(12, be16(ip + 2));
    add(13, 1);
    add(14, last);
    receipt(skb, ip, 0x494e4752, skb->ifindex);
    if (setting(7) == 1)
        skb->cb[0] = 0;
    else if (setting(7) == 2)
        skb->cb[1] ^= 1;
    return 1;
}

/* Runs after the actual ct clear action, still in the same tc_run. */
SEC("classifier/handoff")
int handoff(struct __sk_buff *skb)
{
    unsigned char ip[20], last;
    int valid = full_udp(skb, ip, &last) &&
        (skb->ifindex == setting(1) || skb->ifindex == setting(6)) &&
        skb->cb[0] == 0x494e4752 && skb->cb[1] == setting(4) &&
        skb->cb[2] == setting(5) && skb->cb[3] == skb->ifindex &&
        skb->cb[4] == (identity(ip) ^ skb->ifindex);
    clear_receipt(skb);
    if (!valid) {
        add(18, 1);
        return 0;
    }
    add(15, 1);
    return 1;
}

SEC("classifier/observe")
int observe(struct __sk_buff *skb)
{
    unsigned char ip[20], last;
    if ((skb->ifindex != setting(0) && skb->ifindex != setting(8)) ||
        !full_udp(skb, ip, &last) || ip[8] != 63) {
        add(5, 1);
        return 0;
    }
    add(0, 1);
    add(1, be16(ip + 2));
    add(6, last);
    add(7, be16(ip + 2) == 65535);
    add(8, 1);
    receipt(skb, ip, 0x46524147, setting(2));
    __u32 mode = setting(3);
    if (mode == 1)
        skb->cb[0] = 0;
    else if (mode == 2)
        skb->cb[1] ^= 1;
    return 1;
}

SEC("classifier/release")
int release(struct __sk_buff *skb)
{
    unsigned char ip[20];
    if (skb->ifindex != setting(2) ||
        bpf_skb_load_bytes(skb, 14, ip, 20) || ip[0] != 0x45)
        return TC_ACT_SHOT;
    __u32 incoming = skb->ingress_ifindex;
    if (incoming == setting(0) || incoming == setting(8)) {
        int valid = skb->cb[0] == 0x46524147 && skb->cb[1] == setting(4) &&
            skb->cb[2] == setting(5) && skb->cb[3] == skb->ifindex &&
            skb->cb[4] == (identity(ip) ^ incoming);
        clear_receipt(skb);
        if (!valid) {
            add(3, 1);
            return TC_ACT_SHOT;
        }
        if (be16(ip + 2) > 1500 || ip[8] != 63) {
            add(10, 1);
            return TC_ACT_SHOT;
        }
        add(2, 1);
        return TC_ACT_OK;
    }
    if (incoming == setting(1) || incoming == setting(6)) {
        clear_receipt(skb);
        add(4, 1);
        return TC_ACT_UNSPEC;
    }
    add(11, 1);
    return TC_ACT_SHOT;
}

/* Negative control: a direct second ct stage inherits IP_CT_UNTRACKED and
 * receives fragments, not a complete datagram. It always drops, never grants. */
SEC("classifier/pitfall")
int pitfall(struct __sk_buff *skb)
{
    unsigned char ip[20];
    if (!bpf_skb_load_bytes(skb, 14, ip, 20) && ip[0] == 0x45)
        add((be16(ip + 6) & 0x3fff) ? 16 : 17, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
