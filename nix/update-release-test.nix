# Actual packaged CLI + real Ed25519 proofs on OS releases unlike the package.
# This tests the authenticity/version gate, NOT a bootable artifact or A/B write.
{ pkgs, sentinel }:
let
  publish = pkgs.writeText "publish-version-gate-fixture.py" ''
    import base64, hashlib, json, os, pathlib, subprocess, sys
    os.umask(0o077)
    root = pathlib.Path('/run/qa-release')
    root.mkdir(mode=0o700, exist_ok=True)
    key, public = root/'private.pem', root/'public.pem'
    if not key.exists():
        subprocess.run(['${pkgs.openssl}/bin/openssl','genpkey','-algorithm','ed25519','-out',str(key)],check=True,capture_output=True)
        subprocess.run(['${pkgs.openssl}/bin/openssl','pkey','-in',str(key),'-pubout','-out',str(public)],check=True,capture_output=True)
    # Deliberately non-bootable crypto fixture. No test claims a real slot write.
    image = root/'fixture.raw'
    image.write_bytes(b'QA signed version gate; not a bootable appliance\n')
    manifest = {'version':sys.argv[1], 'image':image.name,
                'sha256':hashlib.sha256(image.read_bytes()).hexdigest(),
                'product':'velstra-sentinel'}
    body = json.dumps(manifest,separators=(',',':')).encode()
    (root/'manifest.json').write_bytes(body)
    subprocess.run(['${pkgs.openssl}/bin/openssl','pkeyutl','-sign','-rawin','-inkey',str(key),
                    '-in',str(root/'manifest.json'),'-out',str(root/'manifest.json.sig')],check=True,capture_output=True)
    signature = (root/'manifest.json.sig').read_bytes()
    subprocess.run(['${pkgs.openssl}/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(public),
                    '-in',str(root/'manifest.json'),'-sigfile',str(root/'manifest.json.sig')],check=True,capture_output=True)
    (root/'release.json').write_text(json.dumps({'schema':1,'manifest':base64.b64encode(body).decode(),
                                               'signature':base64.b64encode(signature).decode()}))
  '';
  node = version: {
    system.image.version = version;
    virtualisation.memorySize = 768;
    environment.systemPackages = [ sentinel pkgs.openssl pkgs.python3 ];
    environment.etc."qa-release/appliance.toml".text = ''
      [system]
      hostname = "qa-release"
      [update]
      url = "file:///run/qa-release"
      public-key = "file:/run/qa-release/public.pem"
    '';
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-update-release-floor";
  globalTimeout = 300;
  nodes = {
    current = node "2.0.0-qa7";
    early = node "0.0.1-lts";
    invalid = node "latest";
  };
  testScript = ''
    import shlex
    start_all()
    command = "env SENTINEL_CONFIG=/etc/qa-release/appliance.toml SENTINEL_UPDATE_STATUS=/run/qa-release/status.json sentinel "

    def publish(node, version):
        node.succeed("${pkgs.python3}/bin/python3 ${publish} " + shlex.quote(version))

    def execute(node, args):
        return node.execute(command + args + " 2>&1")

    def local(version_node):
        return execute(version_node, "update /run/qa-release/fixture.raw --pubkey file:/run/qa-release/public.pem --signature /run/qa-release/manifest.json.sig")

    for n in (current, early, invalid):
        n.wait_for_unit("multi-user.target")
        n.succeed("test ! -e /run/qa-release")

    with subtest("a genuine image replay above package1.0.0 is not a new release"):
        publish(current, "2.0.0-qa6")
        status, out = execute(current, "update check")
        assert status == 0 and "NOT an update" in out and "running release 2.0.0-qa7" in out, out
        status, out = execute(current, "update install")
        assert status != 0 and "OLDER" in out and "running 2.0.0-qa7" in out, out
        assert "image SHA-256 verified" not in out and "could not resolve the source disk" not in out, out
        status, out = local(current)
        assert status != 0 and "signature verified" in out and "OLDER" in out, out
        assert "could not resolve the source disk" not in out, out

    with subtest("same and newer signed image versions remain available"):
        for version in ("2.0.0-qa7", "2.0.0-qa8"):
            publish(current, version)
            status, out = execute(current, "update check")
            assert status == 0 and "update available:" in out and "NOT an update" not in out and version in out, out

    with subtest("a legitimate early image series is not compared to package1.0.0"):
        publish(early, "0.0.2-lts")
        status, out = execute(early, "update check")
        assert status == 0 and "update available:" in out and "NOT an update" not in out, out
        status, out = execute(early, "update install")
        assert status != 0 and "image SHA-256 verified" in out and "could not resolve the source disk" in out, out
        assert "OLDER" not in out, out

    with subtest("the explicit old-image exception still requires a verified image"):
        publish(current, "2.0.0-qa6")
        status, out = execute(current, "update install --allow-downgrade")
        assert status != 0 and "--allow-downgrade" in out and "image SHA-256 verified" in out, out
        assert "could not resolve the source disk" in out, out

    with subtest("an unusable declared running release fails closed"):
        publish(invalid, "99.0.0")
        for args in ("update check", "update install", "update install --allow-downgrade"):
            status, out = execute(invalid, args)
            assert status != 0 and 'running image release "latest"' in out and "refusing" in out, out
            assert "image SHA-256 verified" not in out and "could not resolve the source disk" not in out, out
        status, out = local(invalid)
        assert status != 0 and "signature verified" in out and 'running image release "latest"' in out, out

    with subtest("modifying the offered version without resigning is still refused"):
        publish(current, "2.0.0-qa8")
        current.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(
            "import base64,json,pathlib; p=pathlib.Path('/run/qa-release/release.json'); e=json.loads(p.read_text()); "
            "m=json.loads(base64.b64decode(e['manifest'])); m['version']='99.0.0'; "
            "e['manifest']=base64.b64encode(json.dumps(m).encode()).decode(); p.write_text(json.dumps(e))"))
        status, out = execute(current, "update check")
        assert status != 0 and "signature verification failed" in out.lower(), out
  '';
}
