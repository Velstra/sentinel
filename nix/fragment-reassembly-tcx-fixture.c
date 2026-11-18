/* The combined fixture is force-included by the Nix build. New programs only
 * model TCX dispatch/order; they are not the production Fabric classifier. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u32);
} gate_settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} gate_counters SEC(".maps");

static __always_inline __u32 gate_setting(__u32 key)
{
    __u32 *value = bpf_map_lookup_elem(&gate_settings, &key);
    return value ? *value : 0;
}

static __always_inline int gate(struct __sk_buff *skb, __u32 direction)
{
    unsigned char ip[20];
    if (bpf_skb_load_bytes(skb, 14, ip, 20) || ip[0] != 0x45 || ip[9] != 17 ||
        ip[12] != 198 || ip[13] != 18 || ip[14] != 1 || ip[15] != 2 ||
        ip[16] != 198 || ip[17] != 18 || ip[18] != 2 || ip[19] != 2)
        return TC_ACT_UNSPEC;
    __u64 *count = bpf_map_lookup_elem(&gate_counters, &direction);
    if (count)
        __sync_fetch_and_add(count, 1);
    __u32 mode = gate_setting(direction);
    if (mode == 1)
        return TC_ACT_OK; /* Deliberately unsafe order-control: skip legacy. */
    if (mode == 2 || (mode == 3 && !(gate_setting(2) & (1U << direction))))
        return TC_ACT_SHOT;
    return TC_ACT_UNSPEC; /* TCX_NEXT: continue into the installed legacy chain. */
}

SEC("classifier/gate_in")
int gate_in(struct __sk_buff *skb)
{
    return gate(skb, 0);
}

SEC("classifier/gate_out")
int gate_out(struct __sk_buff *skb)
{
    return gate(skb, 1);
}
