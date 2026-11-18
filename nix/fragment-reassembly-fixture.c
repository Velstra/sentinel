/* Isolated kernel feasibility fixture, NOT the Sentinel/Fabric dataplane. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u32);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 12);
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

/* Volatile individual context stores prevent LLVM turning this into memset
 * through a modified ctx pointer, which the BPF verifier correctly rejects. */
static __always_inline void clear_receipt(struct __sk_buff *skb)
{
    volatile struct __sk_buff *ctx = skb;
    ctx->cb[0] = 0;
    ctx->cb[1] = 0;
    ctx->cb[2] = 0;
    ctx->cb[3] = 0;
    ctx->cb[4] = 0;
}

/* Non-direct-action classifier: only return 1 after complete observation.
 * Its external actions are ct clear, then mirred. Every miss hits a final drop.
 * No permission/flow state is created and no packet payload is translated. */
SEC("classifier/observe")
int observe(struct __sk_buff *skb)
{
    unsigned char ip[20], udp[8], last;
    if (skb->ifindex != setting(0) ||
        bpf_skb_load_bytes(skb, 14, ip, sizeof(ip)) || ip[0] != 0x45 ||
        ip[9] != 17 || (be16(ip + 6) & 0x3fff))
        goto malformed;
    __u16 total = be16(ip + 2);
    if (total < 28 || skb->len != (__u32)total + 14 ||
        bpf_skb_load_bytes(skb, 34, udp, sizeof(udp)) ||
        be16(udp + 4) != total - 20 ||
        bpf_skb_load_bytes(skb, (__u32)total + 13, &last, 1))
        goto malformed;
    add(0, 1);
    add(1, total);
    add(6, last);
    add(7, total == 65535);
    add(8, ip[8] == 63);
    skb->cb[0] = 0x46524147;
    skb->cb[1] = setting(4);
    skb->cb[2] = setting(5);
    skb->cb[3] = setting(2);
    skb->cb[4] = identity(ip);
    __u32 mode = setting(3);
    if (mode == 1)
        skb->cb[0] = 0;
    else if (mode == 2)
        skb->cb[1] ^= 1;
    else if (mode == 3)
        skb->cb[3] ^= 1;
    else if (mode == 4)
        skb->cb[4] ^= 1;
    return 1;
malformed:
    add(5, 1);
    return 0;
}

/* Direct-action guard. The kernel assigns skb_iif on mirred re-entry.
 * A wire payload/mark never authorizes the staging-to-physical handoff. */
SEC("classifier/release")
int release(struct __sk_buff *skb)
{
    unsigned char ip[20];
    if (skb->ifindex != setting(2) ||
        bpf_skb_load_bytes(skb, 14, ip, sizeof(ip)) || ip[0] != 0x45)
        return TC_ACT_SHOT;
    if (skb->ingress_ifindex == setting(0)) {
        int valid = skb->cb[0] == 0x46524147 &&
            skb->cb[1] == setting(4) && skb->cb[2] == setting(5) &&
            skb->cb[3] == skb->ifindex && skb->cb[4] == identity(ip);
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
    if (skb->ingress_ifindex == setting(1)) {
        clear_receipt(skb);
        add(4, 1);
        return TC_ACT_UNSPEC;
    }
    add(11, 1);
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
