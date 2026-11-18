# Summary

[Sentinel operator guide](introduction.md)

# Try and operate
- [Start a VM](operations/quickstart.md)
- [Install to disk](operations/install.md)
- [Apply a change remotely](operations/configure.md)
- [Stage an appliance update](operations/update.md)
- [Choose an HA election mode](operations/high-availability.md)
  - [HA configuration reference](operations/ha-reference.md)
- [Inspect management transactions](operations/management-api.md)
- [Enroll in fleet management](operations/fleet.md)

# Configuration cookbook
- [Use the configuration CLI](handbook/cli.md)
- [System and management](handbook/system.md)
- [Interfaces and addressing](handbook/interfaces.md)
- [Firewall, NAT and packet tracing](handbook/firewall.md)
- [Routing protocols](handbook/routing.md)
- [Network services](handbook/services.md)
- [VPN and certificates](handbook/vpn.md)
- [Multi-WAN and traffic steering](handbook/multiwan.md)
- [Worked configurations](handbook/examples.md)

# How it works
- [Appliance components](architecture/overview.md)
- [Run, confirm and persist](architecture/commit-model.md)
- [A/B slot selection](architecture/ab-updates.md)
- [Verified storage](architecture/verified-boot.md)
- [UEFI Secure Boot](architecture/secure-boot.md)

# Build and validate
- [Build prerequisites](building/prerequisites.md)
- [Build an image](building/images.md)
- [Build the installer](building/iso.md)
- [Build the CLI and agent](building/cli.md)
- [Reproduce a build](building/reproducibility.md)
- [Verify the source SBOM](building/sbom.md)
- [Flake outputs](reference/flake-outputs.md)
- [Select a test](reference/tests.md)
  - [Console tests](reference/console.md)

# Design history
- [Original OS proposal](appendix/design-notes-os.md)
- [Original commit proposal](appendix/design-notes-commit.md)
