# Built-in skill sources

The native-debugging, tmux-debugging, and finding-review skills adapt selected techniques from [0RAYS/codex-auditor](https://github.com/0RAYS/codex-auditor/tree/5974e700bf5b44f10d885bb238dd8bcab8f42145/skills), pinned at commit `5974e700bf5b44f10d885bb238dd8bcab8f42145` (MIT, copyright 2026 RcoketDev). The upstream license is retained in LICENSE.codex-auditor.

Adaptations use this harness's actual tools, deadlines, process cleanup, and JSON protocol. Optional debugger installations, fixed report paths, upstream scoring fields, large manuals, and external scripts are not bundled. code-audit and poc-validation are original guidance for this harness.

The Foundry, GDB, Node Inspector, and pwntools helpers are original implementations against their documented APIs. Their skill entrypoints link the relevant upstream documentation; no debugger distribution or forge-std checkout is bundled.

The `nvd-cve` and `gh-advisory` skill topics were informed by
[`irrit-us/agent_misc` skills](https://github.com/irrit-us/agent_misc/tree/62fd91ad5209f9de5e98a52eb04abb3589e95bdf/skills)
at commit `62fd91ad5209f9de5e98a52eb04abb3589e95bdf`. Their concise text
and examples here were written for this harness using the current official NVD
and GitHub REST documentation; the upstream manuals were not copied. The `cvss`
skill is original guidance based on FIRST's v4.0 and v3.1 specifications.

`audit-context-building` adapts the context-mapping method from
[Trail of Bits' skill](https://github.com/trailofbits/skills/tree/442fc9d6c89b1e937e6f7a477e7071ea75fcbea4/plugins/audit-context-building/skills/audit-context-building)
by Omar Inuwa, pinned at commit `442fc9d6c89b1e937e6f7a477e7071ea75fcbea4`.
The adapted skill and its two references are licensed CC BY-SA 4.0; the upstream
license text is retained in `LICENSE.trailofbits-CC-BY-SA-4.0`. We rewrote the
entrypoint and references for bounded single-agent use, removed the upstream
workflow/subagent dispatch, and kept the function-assumption and call-continuity
method. No upstream JavaScript workflow, agents, fixtures, or assets are bundled.
