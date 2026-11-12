# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues on `Synthminds/rea`. Use the `gh` CLI where its GraphQL API answers. If a host returns `HTTP 403: GitHub GraphQL is not available` for `gh issue`, `gh pr` or `gh label`, use `gh api` REST calls or the [GitHub MCP equivalents](#github-mcp-equivalents) below.

## Status: Issues are enabled

GitHub repository metadata reports `has_issues: true` on `Synthminds/rea`; issues [#6](https://github.com/Synthminds/rea/issues/6) and [#7](https://github.com/Synthminds/rea/issues/7) are open. This was checked on 2026-11-12 UTC. Recheck live metadata before relying on this snapshot. Enabled Issues do not grant publication authority: follow the user's requested scope before creating issues, comments or labels. Return a draft when publication is not authorized.

Of the roles in `docs/agents/triage-labels.md`, only `bug`, `enhancement` and `wontfix` have existing labels. `needs-triage`, `needs-info`, `ready-for-agent` and `ready-for-human` are not configured. Do not pass them as existing labels or invent substitute mappings; settle the intended mapping before creating a missing label.

The inherited issue forms in `.github/ISSUE_TEMPLATE/` apply `bug`, `enhancement` or `documentation` plus `triage`, and their links point at the upstream `morluto/rea`. `triage` is not one of the triage labels, and the fork has no such label.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json title,state,labels,body,comments --jq '.title, .state, ([.labels[].name] | join(", ")), .body, (.comments[] | "--- \(.author.login): \(.body)")'`. Piped, `gh issue view --comments` prints the comments alone, without the body.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **List children**: the open issues whose `## Parent` section names `<number>`, each with its count of open blockers: `gh api 'repos/{owner}/{repo}/issues?state=open&per_page=100' --paginate --jq '.[] | select(.body // "" | test("## Parent\\s+#<number>\\b")) | "\(.number) blocked_by=\(.issue_dependencies_summary.blocked_by) \(.title)"'`, plus any sub-issues (`gh api repos/{owner}/{repo}/issues/<number>/sub_issues --paginate --jq '.[] | select(.state == "open") | "\(.number) blocked_by=\(.issue_dependencies_summary.blocked_by) \(.title)"'`).
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "<name>"` or `--remove-label "<name>"`
- **Create a missing label**: `--label` / `--add-label` fails on a label the repo does not have. Check the current inventory with `gh label list --json name,description`. If label creation is authorized and the mapping is settled, create it first with `gh label create "<name>"`. Do not overwrite an existing label merely to make a workflow fit.
- **Close**: `gh issue close <number> --comment "..."`

This clone's `origin` is `Synthminds/rea`, a fork of `morluto/rea`. Run every `gh` command with `GH_REPO=Synthminds/rea`, which also fills `{owner}/{repo}` in `gh api` paths, so nothing lands on the upstream. `<owner>/<repo>` below means `Synthminds/rea`. Never file on `morluto/rea` from here: upstream reports follow "Reporting issues" in `CONTRIBUTING.md` and need the owner's request.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number> --json title,state,body,comments --jq '.title, .state, .body, (.comments[] | "--- \(.author.login): \(.body)")'` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list` has no author association field, so use the REST API: `gh api 'repos/{owner}/{repo}/pulls?state=open' --paginate --jq '[.[] | select(.author_association | IN("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "NONE")) | {number, title, body, author: .user.login, labels: [.labels[].name]}]'`. This drops `OWNER`/`MEMBER`/`COLLABORATOR`. Read each PR's comments with `gh pr view`.
- **Comment / label / close**: `gh pr comment`, `gh pr close`, and `gh pr edit` with `--add-label` or `--remove-label`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve it in one call with `gh api 'repos/{owner}/{repo}/issues/42' --jq 'if .pull_request then "pr" else "issue" end'`, which answers for both kinds.

## When a skill says "publish to the issue tracker"

Create a GitHub issue on `Synthminds/rea` when the user has authorized publication. Use the appropriate issue form and existing labels. If publication is outside the requested scope or a required label mapping is unresolved, return the draft and the specific missing decision.

## When a skill says "fetch the issue"

Run the **Read an issue** command above.

## Wayfinding operations

Used by `/wayfinder`; `/to-tickets` uses **Blocking** too. The **map** is a single issue with **child** issues as tickets. The `wayfinder:*` labels in these examples do not currently exist on the fork. Resolve their mapping or authorize their creation before using a label-dependent command.

- **Map**: a single issue labelled `wayfinder:map`, holding the Destination / Notes / Decisions so far / Added so far / Not yet specified / Out of scope body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh api` on the sub-issues endpoint). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). GitHub reports `issue_dependencies_summary.blocked_by` (open blockers only, the live gate). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's children with `gh api repos/<owner>/<repo>/issues/<map>/sub_issues --paginate` (or read the map's task list where sub-issues aren't enabled). Keep the open ones (`state == "open"`), drop any with an open blocker (`issue_dependencies_summary.blocked_by > 0`, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.

## GitHub MCP equivalents

Where `gh` GraphQL returns 403 (Claude Code cloud sessions), use these GitHub MCP tools instead, always with `owner: "Synthminds"` and `repo: "rea"`. Tool names vary by host; use the available equivalent for each operation. The same repository targeting, publication authority and existing-label requirements apply.

| Operation              | GitHub MCP call                                                                                                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create an issue        | `mcp__github__issue_write` with `method: "create"`, `title`, `body` and `labels`                                                                                                                              |
| Read an issue          | `mcp__github__issue_read` with `method: "get"`, then `method: "get_comments"`                                                                                                                                 |
| List issues            | `mcp__github__list_issues` with `state: "OPEN"` and `labels`; `fields` trims the reply                                                                                                                        |
| List children          | `mcp__github__issue_read` with `method: "get_sub_issues"`; for `## Parent` links, list issues with their `body` and match it yourself                                                                         |
| Comment on an issue    | `mcp__github__add_issue_comment` with `issue_number` and `body`                                                                                                                                               |
| Apply / remove labels  | Read the current set with `mcp__github__issue_read` `method: "get_labels"`, then `mcp__github__issue_write` with `method: "update"` and the complete new `labels` list, which replaces the set                |
| Create a missing label | No MCP tool. Check with `mcp__github__get_label`; when the label is missing, ask the owner to create it                                                                                                       |
| Close                  | `mcp__github__add_issue_comment`, then `mcp__github__issue_write` with `method: "update"`, `state: "closed"` and `state_reason: "completed"` or `"not_planned"`                                               |
| Issue or PR for `#42`  | `mcp__github__pull_request_read` with `method: "get"` answers only for a PR; otherwise it is an issue                                                                                                         |
| Read a PR              | `mcp__github__pull_request_read` with `method: "get"`, `"get_comments"` and `"get_diff"`                                                                                                                      |
| List external PRs      | `mcp__github__list_pull_requests` with `state: "open"`; it carries no author association, so drop authors that `mcp__github__list_repository_collaborators` lists                                             |
| Comment / label a PR   | The issue calls above with the PR number as `issue_number`                                                                                                                                                    |
| Close a PR             | `mcp__github__update_pull_request` with `state: "closed"`                                                                                                                                                     |
| Map                    | `mcp__github__issue_write` with `method: "create"` and `labels: ["wayfinder:map"]`                                                                                                                            |
| Child ticket           | `mcp__github__issue_write` with `method: "create"` and `parent_issue_number: <map>`, or `mcp__github__sub_issue_write` with `method: "add"` and the child's database `id` from `issue_read` as `sub_issue_id` |
| Blocking               | No MCP tool reads or writes native dependencies: write and read the `Blocked by: #<n>, #<n>` line instead                                                                                                     |
| Frontier query         | `mcp__github__issue_read` with `method: "get_sub_issues"` on the map, then `method: "get"` on each open child for its assignees and body                                                                      |
| Claim                  | `mcp__github__get_me` for your login, then `mcp__github__issue_write` with `method: "update"` and `assignees: ["<login>"]`, which replaces the assignee list                                                  |
| Resolve                | `mcp__github__add_issue_comment`, then `mcp__github__issue_write` `method: "update"` with `state: "closed"`, then update the map's `body` the same way                                                        |
