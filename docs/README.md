# Documentation map

Use the [current handbook](src/introduction.md) for building, installation and
operation. Start with the [VM quickstart](src/operations/quickstart.md),
[configuration CLI](src/handbook/cli.md), [HA lab guide](src/handbook/ha.md) and
[test commands](src/reference/tests.md). Read
[dataplane limitations](src/reference/dataplane-support.md) before selecting a
test topology.

## Development evidence, not operator instructions

Files named `qa-*.md`, `security-*-YYYY-MM-DD.md` and the dated OTA notes are
retained development receipts. Their pass/fail statements apply only to the
recorded source, image and test scope. They are not a current release verdict;
later fixes do not erase the original failures. Review attachments and logs for
credentials before copying any evidence into a public report.

The phase documents are historical implementation records, superseded for
operator setup by these handbook chapters:

| Historical record | Current entry point |
| --- | --- |
| [ha-phase3.md](ha-phase3.md) | [HA modes, pairing and recovery](src/handbook/ha.md) |
| [management-phase4.md](management-phase4.md) | [Management services](src/handbook/services.md#web-console) and [safe configuration](src/operations/configure.md) |
| [fleet-phase5.md](fleet-phase5.md) | [Fleet enrollment](src/handbook/fleet.md) |

`DESIGN.md`, `UX-CONTRACT.md` and `premium-ui.json` at the repository root are
development/design inputs, not supported-product specifications. Historical
appendices inside the book are marked as superseded. A future evidence archive
must preserve provenance and existing links; deleting documents does not remove
them from public Git history. No history rewrite or publication-privacy change
is performed by this documentation cleanup.

## Build the handbook

With mdBook installed, from the repository root:

```sh
mdbook build docs
```

The book refuses missing chapters in `SUMMARY.md`. A rendered book still needs
link review and a check that commands match the current source; rendering alone
does not execute the installation or release procedures.
