# Triage Labels

The skills speak in terms of seven canonical triage roles: two category roles and five state roles. This file records which roles have actual labels in this repo's issue tracker; unconfigured roles have no mapping.

| Label in supermatt | Label in our tracker | Meaning                                  |
| ------------------ | -------------------- | ---------------------------------------- |
| `bug`              | `bug`                | Something is broken                      |
| `enhancement`      | `enhancement`        | New feature or improvement               |
| `needs-triage`     | Not configured       | Maintainer needs to evaluate this issue  |
| `needs-info`       | Not configured       | Waiting on reporter for more information |
| `ready-for-agent`  | Not configured       | Fully specified, ready for an AFK agent  |
| `ready-for-human`  | Not configured       | Requires human implementation            |
| `wontfix`          | `wontfix`            | Will not be actioned                     |

Checked on 2026-11-12 UTC: the repository labels are `accessibility`, `bug`, `documentation`, `duplicate`, `enhancement`, `good first issue`, `help wanted`, `invalid`, `question` and `wontfix`. Recheck with `gh label list --repo Synthminds/rea --json name,description` before writing.

When a skill mentions a role, use its existing mapped label. For an unconfigured role, resolve the mapping first; do not invent an equivalent label. Label creation requires the user's requested scope. The issue forms also name `triage`, which is absent; it is not an established mapping for `needs-triage`.
