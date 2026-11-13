use super::*;
use serde_json::json;

fn original() -> Value {
    json!({"label":"gpt", "id":"immutable-disk", "device":"/dev/vda", "unit":"sectors",
        "firstlba":2048,"lastlba":9999999,"sectorsize":512,
        "partitions": (1..=6).map(|n| json!({"node":format!("/dev/vda{n}"),
            "start":n * 1000,"size":1000,"uuid":format!("00000000-0000-0000-0000-{n:012}"),
            "type": match n { 2|4 => VERITY, 3|5 => USR, _ => "other" },
            "name": match n { 2 => "sentinel_v1.0.0-lts_verity", 3 => "sentinel_v1.0.0-lts", _ => "other" }})).collect::<Vec<_>>()})
}
fn staged() -> install::StagedImage {
    install::StagedImage {
        active_slot: "sentinel-a".into(),
        staged_slot: "sentinel-b".into(),
        verity_guid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
        store_guid: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into(),
        boot_entry: "sentinel_v1.2.0-lts+3-0.efi".into(),
        uki_sha256: "c".repeat(64),
    }
}
fn written() -> Value {
    let mut after = original();
    after["partitions"][3]["uuid"] = json!(staged().verity_guid);
    after["partitions"][4]["uuid"] = json!(staged().store_guid);
    after["partitions"][3]["name"] = json!("sentinel_v1.2.0-lts_verity");
    after["partitions"][4]["name"] = json!("sentinel_v1.2.0-lts");
    after["partitions"][3]["attrs"] = json!("GUID:60,63");
    after
}
#[test]
fn native_readback_requires_real_target_identity_and_preserves_protected_gpt() {
    validate_table(&original(), "/dev/vda", "sentinel-a", "v1.0.0-lts").unwrap();
    validate_readback(
        &original(),
        &written(),
        "sentinel-a",
        "v1.2.0-lts",
        &staged(),
    )
    .unwrap();
    for field in ["id", "device", "unit", "firstlba", "lastlba", "sectorsize"] {
        let mut bad = written();
        bad[field] = json!("changed");
        assert!(
            validate_readback(&original(), &bad, "sentinel-a", "v1.2.0-lts", &staged()).is_err(),
            "{field}"
        );
    }
    for n in 0..6 {
        for field in ["start", "size", "type", "node", "unexpected"] {
            let mut bad = written();
            bad["partitions"][n][field] = json!("changed");
            assert!(
                validate_readback(&original(), &bad, "sentinel-a", "v1.2.0-lts", &staged())
                    .is_err(),
                "{n}/{field}"
            );
        }
    }
}
#[test]
fn native_readback_wrong_duplicate_zero_guid_label_slot_entry_and_hash_are_refused() {
    for n in 0..6 {
        for field in ["uuid", "name"] {
            let mut bad = written();
            bad["partitions"][n][field] = json!("changed");
            assert!(
                validate_readback(&original(), &bad, "sentinel-a", "v1.2.0-lts", &staged())
                    .is_err()
            );
        }
    }
    for value in [
        original()["partitions"][1]["uuid"].clone(),
        json!(staged().store_guid),
        json!("00000000-0000-0000-0000-000000000000"),
    ] {
        let mut bad = written();
        bad["partitions"][3]["uuid"] = value;
        assert!(
            validate_readback(&original(), &bad, "sentinel-a", "v1.2.0-lts", &staged()).is_err()
        );
    }
    for field in [
        "active_slot",
        "staged_slot",
        "boot_entry",
        "uki_sha256",
        "verity_guid",
        "store_guid",
    ] {
        let mut bad = serde_json::to_value(staged()).unwrap();
        bad[field] = json!("invalid");
        let bad = serde_json::from_value(bad).unwrap();
        assert!(
            validate_readback(&original(), &written(), "sentinel-a", "v1.2.0-lts", &bad).is_err(),
            "{field}"
        );
    }
}
#[test]
fn native_preflight_refuses_ambiguous_disks_and_partial_running_slots() {
    for field in ["label", "device", "unit"] {
        let mut bad = original();
        bad[field] = json!("changed");
        assert!(validate_table(&bad, "/dev/vda", "sentinel-a", "v1.0.0-lts").is_err());
    }
    for n in 0..6 {
        for field in ["node", "uuid", "start", "size"] {
            let mut bad = original();
            bad["partitions"][n][field] = json!(null);
            assert!(validate_table(&bad, "/dev/vda", "sentinel-a", "v1.0.0-lts").is_err());
        }
    }
    for n in 1..=4 {
        let mut bad = original();
        bad["partitions"][n]["type"] = json!("wrong");
        assert!(validate_table(&bad, "/dev/vda", "sentinel-a", "v1.0.0-lts").is_err());
    }
    assert!(validate_table(&original(), "/dev/vda", "sentinel-b", "v1.0.0-lts").is_err());
}

#[test]
fn native_readback_covers_b_to_a_and_nvme_partition_paths() {
    let mut before = original();
    before["partitions"][1]["name"] = json!("other");
    before["partitions"][2]["name"] = json!("other");
    before["partitions"][3]["name"] = json!("sentinel_v1.0.0-lts_verity");
    before["partitions"][4]["name"] = json!("sentinel_v1.0.0-lts");
    let mut after = before.clone();
    let mut result = staged();
    result.active_slot = "sentinel-b".into();
    result.staged_slot = "sentinel-a".into();
    after["partitions"][1]["uuid"] = json!(result.verity_guid);
    after["partitions"][2]["uuid"] = json!(result.store_guid);
    after["partitions"][1]["name"] = json!("sentinel_v1.2.0-lts_verity");
    after["partitions"][2]["name"] = json!("sentinel_v1.2.0-lts");
    validate_table(&before, "/dev/vda", "sentinel-b", "v1.0.0-lts").unwrap();
    validate_readback(&before, &after, "sentinel-b", "v1.2.0-lts", &result).unwrap();
    before["device"] = json!("/dev/nvme0n1");
    for n in 0..6 {
        before["partitions"][n]["node"] = json!(format!("/dev/nvme0n1p{}", n + 1));
    }
    validate_table(&before, "/dev/nvme0n1", "sentinel-b", "v1.0.0-lts").unwrap();
    before["partitions"][2]["node"] = json!("/dev/nvme0n13");
    assert!(validate_table(&before, "/dev/nvme0n1", "sentinel-b", "v1.0.0-lts").is_err());
}
