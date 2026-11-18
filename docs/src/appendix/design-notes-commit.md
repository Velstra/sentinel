# Original commit proposal

<a id="the-commit-model--how-commit-activates-config-on-an-immutable-appliance"></a><a id="the-problem"></a><a id="decision-rebuild-on-commit-one-model-for-everything"></a><a id="how-it-works"></a><a id="1-the-flake--config-live-on-the-box"></a><a id="2-commit--validate--write--rebuild--switch"></a><a id="3-save-vs-commit"></a><a id="4-rollback-ux"></a><a id="speed--a-commit-does-not-reboot-the-box"></a><a id="optional-firewall-fast-path-sub-second"></a><a id="summary"></a><a id="security"></a><a id="implementation-steps-later"></a>

The original proposal rebuilt a NixOS generation on each configuration change. The implemented CLI compiles the candidate and applies it to running services.

[Read the current architecture](../architecture/commit-model.md). For the complete historical discussion, see the [archived proposal](https://github.com/Velstra/sentinel/blob/f4f1d94c67c6929a8055328397ef6fa6aaefc3db/docs/src/appendix/design-notes-commit.md).
