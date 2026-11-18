# Verify the source software inventory

<a id="software-bill-of-materials"></a>

Public CI produces a CycloneDX 1.6 inventory of the declared Rust and JavaScript dependencies, plus checksums and provenance for the source revision.

## Verify a CI artifact

```sh
sha256sum --check SHA256SUMS
```

Run this in the extracted `sentinel-source-sbom-*` artifact. Inspect `sbom.cdx.json` for components and `sbom.provenance.json` for source and inventory hashes.

## Recreate the inventory

```sh
python3 scripts/generate_sbom.py --output-dir /tmp/sentinel-source-sbom
```

Run from the source checkout with Python 3.11+ and the Syft version pinned by public CI. Choose a fresh output directory.

## Review the correct artifact

A source inventory describes declared dependencies, including development packages. For an appliance approval, request release evidence tied to the actual image digest, including the installed-image inventory and its vulnerability scan.

An inventory is not redistribution notices or proof that license and source-distribution obligations are met. See [licenses and notices](notices.md).
