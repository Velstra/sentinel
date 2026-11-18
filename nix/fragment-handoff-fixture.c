/* Reserved-flow ingress handoff mechanics only. No product policy or NAT. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} handoff_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} handoff_counts SEC(".maps");

struct handoff_ticket {
    __u64 epoch;
    __u64 until_ns;
    __u32 physical;
    __u32 staging;
    __u32 identity;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, struct handoff_ticket);
} tickets SEC(".maps");

static __always_inline __u32 config(__u32 key)
{
    __u32 *v = bpf_map_lookup_elem(&handoff_cfg, &key);
    return v ? *v : 0;
}

static __always_inline void count(__u32 key, __u64 amount)
{
    __u64 *v = bpf_map_lookup_elem(&handoff_counts, &key);
    if (v)
        __sync_fetch_and_add(v, amount);
}

static __always_inline __u16 be16(const unsigned char *p)
{
    return ((__u16)p[0] << 8) | p[1];
}

static __always_inline __u64 epoch(void)
{
    return (__u64)config(2) | ((__u64)config(3) << 32);
}

static __always_inline int target(const unsigned char *ip)
{
    return ip[0] == 0x45 && ip[9] == 17 &&
        ip[12] == 198 && ip[13] == 18 && ip[14] == 1 && ip[15] == 2 &&
        ip[16] == 198 && ip[17] == 18 && ip[18] == 2 && ip[19] == 2;
}

static __always_inline void clear(struct __sk_buff *skb)
{
    volatile struct __sk_buff *ctx = skb;
    ctx->cb[0] = 0;
    ctx->cb[1] = 0;
    ctx->cb[2] = 0;
    ctx->cb[3] = 0;
    ctx->cb[4] = 0;
}

/* Bind the complete header, UDP header/checksum and final payload byte. Not a
 * cryptographic content MAC: the ticket is kernel-local, never wire-carried. */
static __always_inline int identity(struct __sk_buff *skb, unsigned char *ip,
                                   __u32 *result)
{
    unsigned char udp[8], last;
    __u16 total = be16(ip + 2);
    if (!target(ip) || (be16(ip + 6) & 0x3fff) || total < 28 ||
        skb->len != (__u32)total + 14 ||
        bpf_skb_load_bytes(skb, 34, udp, 8) || be16(udp + 4) != total - 20 ||
        bpf_skb_load_bytes(skb, (__u32)total + 13, &last, 1))
        return 0;
    __u32 hash = 0x74cde219;
#pragma unroll
    for (int i = 0; i < 20; i++)
        hash = (hash * 33) ^ ip[i];
#pragma unroll
    for (int i = 0; i < 8; i++)
        hash = (hash * 33) ^ udp[i];
    *result = hash ^ last;
    return 1;
}

SEC("xdp")
int wire_xdp(struct xdp_md *ctx)
{
    unsigned char *data = (void *)(long)ctx->data;
    unsigned char *end = (void *)(long)ctx->data_end;
    if (data + 34 <= end && target(data + 14))
        count(0, 1);
    return XDP_PASS;
}

SEC("tc")
int phys_gate(struct __sk_buff *skb)
{
    unsigned char ip[20];
    if (bpf_skb_load_bytes(skb, 14, ip, 20) || !target(ip))
        return TC_ACT_UNSPEC;
    count(1, 1);
    if (skb->ifindex != config(1))
        return TC_ACT_SHOT;
    if (be16(ip + 6) & 0x3fff) {
        clear(skb);
        count(2, 1);
        return bpf_redirect(config(0), 0);
    }
    /* Reserved complete wire datagrams are NOT an ordinary fastpath control.
     * They must not masquerade as an authorized reinjection. */
    __u64 token = (__u64)skb->cb[1] | ((__u64)skb->cb[2] << 32);
    __u32 hash;
    struct handoff_ticket *entry = bpf_map_lookup_elem(&tickets, &token);
    int valid = skb->cb[0] == 0x5449434b && entry &&
        identity(skb, ip, &hash) && entry->epoch == epoch() &&
        entry->until_ns > bpf_ktime_get_ns() && entry->physical == skb->ifindex &&
        entry->staging == config(0) && entry->identity == hash &&
        skb->cb[3] == config(0) && skb->cb[4] == skb->ifindex;
    clear(skb);
    if (!valid) {
        count(4, 1);
        return TC_ACT_SHOT;
    }
    /* Successful deletion is the cross-CPU single-use arbitration. A lookup
     * alone would let two netif_rx queues admit the same token concurrently. */
    if (bpf_map_delete_elem(&tickets, &token)) {
        count(4, 1);
        return TC_ACT_SHOT;
    }
    count(3, 1);
    if (skb->ingress_ifindex == config(1))
        count(7, 1);
    else {
        count(8, 1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_UNSPEC;
}

/* Non-direct-action classifier: authorize and emit one ticket only for a
 * complete datagram on the dedicated drop-default staging device. The ct
 * clear and explicit mirred ingress actions belong to this same filter. */
SEC("tc")
int authorize(struct __sk_buff *skb)
{
    unsigned char ip[20];
    __u32 hash;
    clear(skb);
    if (skb->ifindex != config(0) || bpf_skb_load_bytes(skb, 14, ip, 20) ||
        !identity(skb, ip, &hash) || ip[8] != 64)
        return 0;
    count(6, 1);
    __u32 sequence_key = 14, last_key = 15;
    __u64 *seq = bpf_map_lookup_elem(&handoff_counts, &sequence_key);
    __u64 *last = bpf_map_lookup_elem(&handoff_counts, &last_key);
    if (!seq || !last)
        return 0;
    __u64 token = __sync_fetch_and_add(seq, 1) + 1;
    if (!token)
        return 0;
    __u32 mode = config(4);
    if (mode == 5) {
        token = *last;
    } else {
        struct handoff_ticket value = {
            .epoch = epoch(), .until_ns = bpf_ktime_get_ns() + 2000000000ULL,
            .physical = config(1), .staging = config(0), .identity = hash,
        };
        if (mode == 2)
            value.epoch ^= 1;
        if (mode == 3)
            value.physical ^= 0x100;
        if (mode == 4)
            value.identity ^= 1;
        if (mode == 6)
            value.until_ns = 0;
        if (mode == 7)
            value.staging ^= 0x100;
        if (bpf_map_update_elem(&tickets, &token, &value, BPF_NOEXIST)) {
            count(9, 1);
            return 0;
        }
        *last = token;
    }
    skb->cb[0] = mode == 1 ? 0 : 0x5449434b;
    skb->cb[1] = token;
    skb->cb[2] = token >> 32;
    skb->cb[3] = config(0);
    skb->cb[4] = config(1);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
