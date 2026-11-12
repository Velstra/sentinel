# Real immutable4GiB/10GiB signed HTTPS update. No auxiliary disk/TMPDIR.
{ pkgs, self }:
let
  lib = pkgs.lib;
  port = 28483;
  sentinel = self.packages.${pkgs.stdenv.hostPlatform.system}.sentinel;
  pki = pkgs.runCommand "qa-update-capacity-pki" {
    nativeBuildInputs = [ pkgs.openssl ];
    outputs = [ "out" "private" ];
  } ''
    mkdir -p "$out" "$private"
    # Disposable QA material. ONLY public output enters the DUT closure.
    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
      -subj "/CN=Sentinel disposable capacity gate CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout "$private/ca.key" -out "$out/ca.crt"
    openssl req -new -newkey ed25519 -nodes \
      -subj "/CN=Sentinel capacity HTTPS reference" \
      -keyout "$private/tls.key" -out leaf.csr
    openssl x509 -req -in leaf.csr -CA "$out/ca.crt" -CAkey "$private/ca.key" \
      -set_serial 1 -days 3650 \
      -extfile ${pkgs.writeText "qa-capacity-tls.ext" ''
        basicConstraints=critical,CA:FALSE
        keyUsage=critical,digitalSignature
        extendedKeyUsage=serverAuth
        subjectAltName=IP:10.0.2.2,IP:127.0.0.1
      ''} -out "$private/tls.crt"
    openssl genpkey -algorithm ed25519 -out "$private/release.key"
    openssl pkey -in "$private/release.key" -pubout -out "$out/release.pub"
  '';
  base = version: {
    imports = [ self.nixosModules.sentinel ./image.nix ];
    velstra.appliance.imageVersion = version;
    services.velstra.interface = lib.mkForce "eth0";
    security.pki.certificateFiles = [ "${pki}/ca.crt" ];
    environment.etc."qa-capacity-release.pub".source = "${pki}/release.pub";
    environment.etc."qa-update-capacity.py".source = ./update_capacity.py;
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.e2fsprogs ];
    services.velstra.appliance = lib.mkForce (pkgs.writeText "capacity-appliance.toml" ''
      [system]
      hostname = "capacity-fw"
      [[interface]]
      name = "eth0"
      address = "dhcp"
      zone = "wan"
      [update]
      url = "https://10.0.2.2:${toString port}/current"
      public-key = "file:/etc/qa-capacity-release.pub"
      [services.web]
      enable = true
      tls = true
      listen-address = "127.0.0.1"
    '');
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      memorySize = 4096;
      fileSystems = lib.mkVMOverride { };
    };
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-default-capacity-signed-https-update";
  globalTimeout = 1800;
  nodes = {
    donor = {
      imports = [ (base "2.0.2-qa-capacity-update") ];
      system.name = "donor";
      environment.etc."qa-capacity-donor".text = "Real signed OTA donor; not the original slot.\n";
    };
    machine = {
      imports = [ (base "2.0.1-qa-capacity-base") ];
      system.name = "machine";
      # Model one stable virtual hardware identity across both boots, as Nova
      # does. Do not inject/repair the product's volatile /etc/machine-id.
      virtualisation.qemu.options = [ "-uuid 75b6fb89-0399-4b6e-865d-543702a6e25b" ];
    };
  };
  testScript = { nodes, ... }:
  let
    raw = "${nodes.donor.system.build.finalImageSigned}/${nodes.donor.image.filePath}";
    proof = pkgs.runCommand "qa-update-capacity-release" {
      nativeBuildInputs = [ pkgs.openssl pkgs.python3 ];
    } ''
      mkdir -p "$out"
      python3 - ${raw} "$out" ${pki.private}/release.key ${pkgs.openssl}/bin/openssl <<'PY'
      import base64,hashlib,json,pathlib,subprocess,sys
      image,out,key,openssl=sys.argv[1:]
      digest=hashlib.sha256()
      with open(image,"rb") as source:
          while block:=source.read(4*1024**2): digest.update(block)
      out=pathlib.Path(out)
      manifest=json.dumps({"version":"2.0.2-qa-capacity-update","image":"candidate.raw",
                           "sha256":digest.hexdigest(),"product":"velstra-sentinel"},
                          separators=(",",":")).encode()
      (out/"manifest.json").write_bytes(manifest)
      subprocess.run([openssl,"pkeyutl","-sign","-rawin","-inkey",key,
                      "-in",str(out/"manifest.json"),"-out",str(out/"signature")],check=True)
      signature=(out/"signature").read_bytes()
      assert len(signature)==64
      (out/"release.json").write_text(json.dumps({"schema":1,
          "manifest":base64.b64encode(manifest).decode(),
          "signature":base64.b64encode(signature).decode()}))
      PY
    '';
  in ''
    import importlib.util, json, os, re, shlex, subprocess, tempfile, time
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("capacity_reference", "${./update_capacity.py}")
    if spec is None:
        raise RuntimeError("Unable to create the capacity reference module spec")
    loader = spec.loader
    if loader is None:
        raise RuntimeError("Unable to create the capacity reference module loader")
    reference = importlib.util.module_from_spec(spec)
    loader.exec_module(reference)
    candidate = Path("${raw}")
    assert candidate.stat().st_size == 6040866816, candidate.stat()
    manifest = json.loads(Path("${proof}/manifest.json").read_text())
    assert reference.sha_file(candidate) == manifest["sha256"]
    table = json.loads(subprocess.check_output(
        ["${pkgs.util-linux}/bin/sfdisk", "--json", str(candidate)], text=True))["partitiontable"]
    assert table["label"] == "gpt" and table["sectorsize"] == 512 and len(table["partitions"]) == 6
    def partition_hash(number):
        part = table["partitions"][number-1]
        begin, length = part["start"]*512, part["size"]*512
        assert 0 <= begin < begin+length <= candidate.stat().st_size
        import hashlib
        result = hashlib.sha256()
        with candidate.open("rb") as source:
            source.seek(begin)
            while length:
                block = source.read(min(length, 4*1024**2))
                assert block
                result.update(block)
                length -= len(block)
        return result.hexdigest()
    expected = {str(number): partition_hash(number) for number in (2,3)}
    temporary = tempfile.TemporaryDirectory()
    overlay = Path(temporary.name) / "ordinary.qcow2"
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    original = "${nodes.machine.system.build.finalImageSigned}/${nodes.machine.image.filePath}"
    subprocess.run([qemu_img,"create","-f","qcow2","-F","raw","-b",original,str(overlay)],check=True)
    subprocess.run([qemu_img,"resize",str(overlay),"10G"],check=True)
    os.environ["NIX_DISK_IMAGE"] = str(overlay)
    helper = ("${pkgs.python3}/bin/python3 /etc/qa-update-capacity.py"
              " --sentinel ${sentinel}/bin/sentinel"
              " --systemctl ${pkgs.systemd}/bin/systemctl --journalctl ${pkgs.systemd}/bin/journalctl")
    evidence = {"scope":"Plain ext4 immutable4GiB/10GiB only; not LUKS/mdraid/native hardware",
                "RAW_bytes":candidate.stat().st_size,"RAW_SHA256":manifest["sha256"],
                "source_VM_is_the_only_started_node":True,"TMPDIR_override":False,
                "external_auxiliary_disk":False,"manual_bless_or_boot_repair":False}
    server = reference.ReleaseServer(candidate,"${proof}/release.json",
        "${pki.private}/tls.crt","${pki.private}/tls.key",port=${toString port}).start()
    def healthy(trial=False):
        machine.wait_for_unit("multi-user.target")
        # Permanent factory boots do not pull the trial-only boot-complete /
        # bless transaction. Require actual product health, never start/bless it
        # manually; counted update B must still prove the full automatic path.
        for name in reference.UNITS[:4]:
            machine.wait_for_unit(name + ".service")
        if trial:
            for name in reference.UNITS[4:]:
                machine.wait_for_unit(name + ".service")
        command=machine.succeed("systemctl show velstra-boot-verify.service -p ExecStart --value")
        match=re.search(r"path=(/nix/store/[^ ;]+)",command)
        assert match, command
        checker=match[1]
        body=machine.succeed("cat "+shlex.quote(checker))
        assert "boot-health.py verify --sentinel" in body and "bless" not in body and "reboot" not in body, body
        machine.wait_until_succeeds(shlex.quote(checker), timeout=120)
        machine.succeed("test -d /sys/firmware/efi && dmsetup info --target verity usr")
        machine.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    def snapshot():
        return json.loads(machine.succeed(helper + " snapshot", timeout=180))
    def unchanged(before):
        after = snapshot()
        changes = {key: {"before": before.get(key), "after": after.get(key)}
                   for key in before.keys() | after.keys()
                   if before.get(key) != after.get(key)}
        assert after == before, ("A refusal/cancellation changed partitions/GPT/config/identity: "
                                 + json.dumps(changes, sort_keys=True))
        healthy()
    def events_since(index):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            events=server.observed(index)
            if any(e["path"].endswith(".raw") for e in events):
                return events
            time.sleep(0.1)
        return server.observed(index)
    def launch(label):
        machine.succeed("systemd-run --unit=qa-capacity-" + label +
            " --property=RuntimeMaxSec=1000 --collect --no-block " + helper + " transfer " + label)
    def result(label):
        path="/run/qa-capacity-"+label+"/result.json"
        machine.wait_until_succeeds("test -f "+path, timeout=950)
        return json.loads(machine.succeed("cat "+path))
    def ordinary_disk_inventory(rows, floppy):
        # Linux reports the default PC floppy controller as TYPE=disk too.
        # Never hide arbitrary removable/zero-sized/renamed auxiliary storage:
        # only fd0 with independently verified kernel floppy identity qualifies.
        disks=[row for row in rows if row["type"]=="disk"]
        names=[row["name"] for row in disks]
        assert len(names)==len(set(names)) and sorted(names) in (["vda"],["fd0","vda"]), rows
        root=next(row for row in disks if row["name"]=="vda")
        assert root["size"]==10*1024**3 and root["rm"] is False and root["ro"] is False, root
        if "fd0" in names:
            row=next(row for row in disks if row["name"]=="fd0")
            assert floppy is not None, "Actual fd0 sysfs/node observation required"
            assert floppy["class_path"]=="/sys/devices/platform/floppy.0/block/fd0", floppy
            assert floppy["subsystem"]=="/sys/class/block" and floppy["device_subsystem"]=="/sys/bus/platform", floppy
            assert floppy["device_path"]=="/sys/devices/platform/floppy.0" and floppy["driver"]=="/sys/bus/platform/drivers/floppy", floppy
            assert floppy["dev"]=="2:0" and floppy["block_node"] is True and floppy["node_major_minor"]==[2,0], floppy
            # Linux's unknown-media placeholder is0 or8sectors, not an image
            # staging volume. Read/record RO as-is; never set it to obtain pass.
            assert floppy["removable"]==1 and floppy["size_sectors"] in (0,8), floppy
            assert floppy["read_only"] in (0,1) and row["ro"] is bool(floppy["read_only"]), floppy
            assert row["rm"] is True and row["size"]==512*floppy["size_sectors"], row
            assert not any(row.get("mountpoints",[])), row
        else:
            assert floppy is None, "Unexpected unlisted floppy observation"
        return {"actual_block_devices":rows,"fixed_storage_disks":["vda"],
                "verified_kernel_floppy":floppy,"auxiliary_storage_disk":False}
    try:
        machine.start()
        # Factory A is also counted (boot.uki.tries=3). Actual1748 raced this
        # initial transaction; wait for real automatic assessment/blessing
        # before asserting permanent A, never bless it manually.
        healthy(trial=True)
        machine.succeed("test -e /boot/EFI/Linux/sentinel-a.efi && test ! -e /boot/EFI/Linux/sentinel-a+3.efi")
        assert int(machine.succeed("blockdev --getsize64 /dev/vda")) == 10*1024**3
        firmware_uuid = machine.succeed("cat /sys/class/dmi/id/product_uuid").strip().lower()
        assert firmware_uuid == "75b6fb89-0399-4b6e-865d-543702a6e25b", firmware_uuid
        evidence["stable_virtual_hardware_UUID"] = firmware_uuid
        assert machine.succeed("findmnt -n -o SOURCE /var/lib/sentinel").strip() == "/dev/vda6"
        assert int(machine.succeed("df -B1 --output=size /var/lib/sentinel").splitlines()[-1]) > 4*1024**3
        assert int(machine.succeed("df -B1 --output=size /tmp").splitlines()[-1]) < candidate.stat().st_size
        devices=json.loads(machine.succeed("lsblk -J -d -b -o NAME,TYPE,SIZE,RM,RO,MOUNTPOINTS"))["blockdevices"]
        floppy=None
        if any(row["name"]=="fd0" for row in devices):
            inspect_floppy=("from pathlib import Path; import json,os,stat; "
                "p=Path('/sys/class/block/fd0'); d=p/'device'; n=os.stat('/dev/fd0'); "
                "print(json.dumps({'class_path':str(p.resolve(strict=True)), "
                "'subsystem':str((p/'subsystem').resolve(strict=True)), "
                "'device_path':str(d.resolve(strict=True)), "
                "'device_subsystem':str((d/'subsystem').resolve(strict=True)), "
                "'driver':str((d/'driver').resolve(strict=True)), "
                "'dev':(p/'dev').read_text().strip(), 'size_sectors':int((p/'size').read_text()), "
                "'removable':int((p/'removable').read_text()), 'read_only':int((p/'ro').read_text()), "
                "'block_node':stat.S_ISBLK(n.st_mode), 'node_major_minor':[os.major(n.st_rdev),os.minor(n.st_rdev)]}))")
            floppy=json.loads(machine.succeed("${pkgs.python3}/bin/python3 -c "+shlex.quote(inspect_floppy)))
        evidence["ordinary_disk_inventory"]=ordinary_disk_inventory(devices,floppy)
        # Create a genuine saved revision before any preservation claims. This
        # is the ordinary CLI save path, not a fabricated archive fixture.
        saved=machine.succeed("printf '%s\\n' save 'run show version' exit | sentinel configure 2>&1")
        assert "saved /var/lib/sentinel/appliance.toml (persists across reboot)" in saved, saved
        assert "error:" not in saved.lower() and "warning:" not in saved.lower(), saved
        assert "2.0.1-qa-capacity-base" in saved, saved
        machine.succeed("printf persistent-capacity-proof > /var/lib/sentinel/qa-capacity-proof")
        before = snapshot()
        for name in ("appliance.toml", "ssh/ssh_host_ed25519_key", "ssh/ssh_host_ed25519_key.pub",
                     "ssh/ssh_host_rsa_key", "ssh/ssh_host_rsa_key.pub", "web-tls/cert.pem", "web-tls/key.pem"):
            assert name in before["private"], ("missing actual preservation witness",name)
            machine.succeed("test -s " + shlex.quote("/var/lib/sentinel/"+name))
        archives=[name for name in before["private"]
                  if name.startswith("archive/config-") and name.endswith(".toml")]
        assert archives, "No genuine saved configuration revision"
        for name in archives:
            machine.succeed("test -s " + shlex.quote("/var/lib/sentinel/"+name))
        with subtest("protected snapshot remains stable across idle before any update request"):
            # Isolate background filesystem activity from the updater. No unit,
            # mount, configuration or disk state is manually changed here.
            machine.wait_until_succeeds(
                "test \"$(systemctl show boot.mount -p ActiveState --value)\" = inactive",
                timeout=360)
            unchanged(before)
        with subtest("genuine system-CA HTTPS and Ed25519 metadata precede the default download"):
            checked = machine.succeed("env -u TMPDIR -u TMP -u TEMP sentinel update check 2>&1")
            assert manifest["version"] in checked and manifest["sha256"] in checked, checked
            assert server.observed()[-1]["TLS"] in ("TLSv1.2","TLSv1.3")
        with subtest("bad Ed25519 metadata cannot start an image transfer or change target regions"):
            index = server.select("bad-signature")
            status, text = machine.execute("env -u TMPDIR -u TMP -u TEMP sentinel update install --commit 2>&1")
            assert status != 0 and "signature verification FAILED" in text, text
            assert not any(e["path"].endswith(".raw") for e in server.observed(index))
            unchanged(before)
        with subtest("real insufficient ext4 capacity refuses inside a bounded private namespace"):
            index = server.select("good")
            namespace = machine.succeed("readlink /proc/self/ns/mnt").strip()
            low = machine.succeed("${pkgs.util-linux}/bin/unshare --mount " + helper +
                " low-space " + shlex.quote(namespace), timeout=180)
            low = json.loads(low)
            assert low["private_mount_namespace"] and low["bounded_fixture_bytes"] == 128*1024**2
            assert "insufficient persistent update staging capacity" in low["output"]
            assert not any(e["path"].endswith(".raw") for e in server.observed(index))
            unchanged(before)
            evidence["bounded_private_ext4_capacity_refusal"] = low
        with subtest("owner death reaps curl and releases the anonymous stage and update lock"):
            index = server.select("cancel")
            launch("cancel")
            started = json.loads(machine.succeed(helper + " wait-start cancel", timeout=110))
            assert started["actual_anonymous_stage_seen"] and started["label"] == "cancel", started
            status,text=machine.execute("env -u TMPDIR -u TMP -u TEMP sentinel update install --commit 2>&1")
            assert status != 0 and "another update is in progress" in text, text
            machine.succeed(helper + " cancel")
            cancelled = result("cancel")
            assert cancelled["exit"] == -9 and cancelled["samples"], cancelled
            assert cancelled["TMPDIR_TMP_TEMP_unset"]
            machine.wait_until_succeeds(helper + " no-curl", timeout=15)
            wire = events_since(index)
            assert any(e["mode"]=="cancel" and not e["complete"] for e in wire), wire
            unchanged(before)
            evidence["owner_death"] = cancelled
        with subtest("a tampered full six-gigabyte HTTPS RAW fails digest before any slot write"):
            index=server.select("tamper")
            launch("tamper")
            bad=result("tamper")
            assert bad["exit"] != 0 and "image SHA-256 mismatch" in bad["output"], bad
            wire=events_since(index)
            assert any(e["mode"]=="tamper" and e["complete"] and
                       e["bytes"]==candidate.stat().st_size and e["wire_SHA256"]!=manifest["sha256"]
                       for e in wire if e["path"].endswith(".raw")),wire
            unchanged(before)
            evidence["full_RAW_tamper"] = bad
        with subtest("default-capacity signed installation stages exact B without TMPDIR or extra disk"):
            index=server.select("good")
            launch("good")
            good=result("good")
            assert good["exit"] == 0 and "update complete" in good["output"], good
            assert good["TMPDIR_TMP_TEMP_unset"] and good["samples"]
            assert max(s["logical"] for s in good["samples"]) == candidate.stat().st_size
            assert max(s["allocated"] for s in good["samples"]) < 4*1024**3
            assert good["max_RSS"] < 256*1024**2
            assert good["maximum_Shmem"]-good["initial_Shmem"] < 512*1024**2
            assert good["minimum_state_available"] >= 512*1024**2
            assert good["oom_kill_before"] == good["oom_kill_after"]
            wire=events_since(index)
            assert any(e["complete"] and e["bytes"]==candidate.stat().st_size and
                       e["wire_SHA256"]==manifest["sha256"]
                       for e in wire if e["path"].endswith(".raw")),wire
            staged=snapshot()
            assert staged["parts"]["2"]==before["parts"]["2"] and staged["parts"]["3"]==before["parts"]["3"]
            assert staged["parts"]["4"]==expected["2"] and staged["parts"]["5"]==expected["3"]
            assert staged["private"]==before["private"]
            assert staged["machine_id_SHA256"]==before["machine_id_SHA256"]
            assert staged["UKIs"]["sentinel-a.efi"]==before["UKIs"]["sentinel-a.efi"]
            old,new=before["GPT"]["partitiontable"],staged["GPT"]["partitiontable"]
            assert old["id"]==new["id"]
            for index in (0,1,2,5):
                assert old["partitions"][index]==new["partitions"][index]
            for index in (3,4):
                assert old["partitions"][index]["start"]==new["partitions"][index]["start"]
                assert old["partitions"][index]["size"]==new["partitions"][index]["size"]
                assert new["partitions"][index]["uuid"].lower()==table["partitions"][index-2]["uuid"].lower()
                assert new["partitions"][index]["type"].lower()==table["partitions"][index-2]["type"].lower()
            machine.succeed("test -e /boot/EFI/Linux/sentinel-b+3.efi && test -e /boot/EFI/Linux/sentinel-a.efi")
            evidence["default_capacity_stage"]=good
        with subtest("real reboot assesses donor B permanently without manual blessing"):
            machine.shutdown()
            machine.start()
            healthy(trial=True)
            actual=snapshot()
            assert actual["boot_id"]!=before["boot_id"] and actual["private"]==before["private"]
            assert actual["machine_id_SHA256"]==before["machine_id_SHA256"]
            assert machine.succeed("cat /sys/class/dmi/id/product_uuid").strip().lower()==firmware_uuid
            assert actual["parts"]["2"]==before["parts"]["2"] and actual["parts"]["3"]==before["parts"]["3"]
            assert actual["parts"]["4"]==expected["2"] and actual["parts"]["5"]==expected["3"]
            assert actual["UKIs"]["sentinel-a.efi"]==before["UKIs"]["sentinel-a.efi"]
            assert actual["GPT"]==staged["GPT"]
            assert actual["GPT_headers"]==staged["GPT_headers"]
            version=machine.succeed("sentinel show version")
            assert manifest["version"] in version and "slot sentinel-b" in version, version
            machine.succeed("test -e /etc/qa-capacity-donor && test -e /boot/EFI/Linux/sentinel-b.efi && test ! -e /boot/EFI/Linux/sentinel-b+3.efi")
            assert "/dev/vda5" in machine.succeed("lsblk -nsro PATH /dev/mapper/usr").splitlines()
            assert machine.succeed("cat /var/lib/sentinel/qa-capacity-proof")=="persistent-capacity-proof"
            evidence["automatic_assessed_B_boot"]={"version":version,"protected_A_exact":True,
                "config_keys_archives_preserved":True,"boot_id_changed":True,
                "raw_machine_id_preserved":True,"staged_GPT_bytes_preserved":True}
        evidence["transport_events"]=server.observed()
        Path(os.environ["out"],"default-capacity-update.json").write_text(json.dumps(evidence,indent=2))
    finally:
        server.close()
  '';
}
