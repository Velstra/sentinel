# Summary

[Introduction](introduction.md)

# Building

- [Prerequisites](building/prerequisites.md)
- [Building images](building/images.md)
- [Building the installer ISO](building/iso.md)
- [Building the CLI & agent](building/cli.md)
- [Reproducibility & pinned hashes](building/reproducibility.md)

# Architecture

- [The appliance model](architecture/overview.md)
- [Verified boot (dm-verity)](architecture/verified-boot.md)
- [A/B update slots](architecture/ab-updates.md)
- [Secure Boot](architecture/secure-boot.md)
- [The commit model (runtime apply)](architecture/commit-model.md)

# Operations

- [Installing to disk](operations/install.md)
- [Configuring the appliance](operations/configure.md)
- [Updating (A/B + rollback)](operations/update.md)

# Reference

- [Flake outputs](reference/flake-outputs.md)
- [Test suite (nixosTests)](reference/tests.md)

---

# Appendix — historical design notes

- [Original OS design notes](appendix/design-notes-os.md)
- [Original commit-model notes](appendix/design-notes-commit.md)
