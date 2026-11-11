# Software bill of materials

Public CI produces a standard CycloneDX 1.6 JSON source SBOM on every pull request,
push to main and manual run. Download the `sentinel-source-sbom-*` Actions
artifact: it contains `sbom.cdx.json`, `sbom.provenance.json` and `SHA256SUMS`.

The pinned Syft cataloger reads only `Cargo.toml`, `Cargo.lock`, `ui/package.json`
and `ui/package-lock.json`, copied into a clean temporary directory. Cargo and
npm catalogs must both be nonempty. Build caches, local QA copies, private
credentials and untracked files are not scanned or uploaded. Source input
hashes, the exact Git commit and the SBOM hash are recorded; source changes
during generation and overwriting old evidence are refused.

Run the same generator locally with Python 3.11+ and Syft 1.54.1:

```sh
python3 scripts/generate_sbom.py --output-dir /tmp/sentinel-source-sbom
cd /tmp/sentinel-source-sbom
sha256sum --check SHA256SUMS
```

This inventories declared application dependencies, including development
dependencies. It is **not an installed-image SBOM**, a clean CVE scan, or an
appliance certification. NixOS packages, the kernel, Fabric/Wren runtime inputs
and their precise installed outputs must be inventoried separately from the
actual built release image. Final release SBOM/CVE evidence must bind that
image's hash; the source artifact must never substitute for it.
