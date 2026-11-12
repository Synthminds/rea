---
name: rea-run
description: Build REA from a source checkout and drive its CLI and MCP server, directly or in tmux, to see a change working. Use to run, smoke-test or QA REA; choosing tests for a change belongs to docs/testing.md.
---

# REA run

Get a current build, then exercise REA the way its users do: one-shot CLI
commands, the interactive `rea setup`, and the MCP server on stdio. Follow the
checkout's [development rules](../../../AGENTS.md#development) and
[testing guide](../../../docs/testing.md); this skill adds the launch recipe,
not permission to analyze third-party targets, publish or merge.

Keep scratch state and evidence in `DIR=$(mktemp -d)`, outside the checkout.
Pass absolute target paths: the CLI resolves relative paths against its
working directory, and MCP clients must send absolute paths.

## Build

Use the toolchain from `.nvmrc` and `package.json#packageManager`, and check
`node --version` against `package.json#engines` before building. Cursor Cloud
installs the pinned toolchain under `/usr/local/bin` behind an older Node.js;
there, prefix `PATH="/usr/local/bin:$PATH"`.

```sh
npm ci                 # locked dependencies and Husky hooks; needs the npm registry
npm run build:cached   # dist/ runtime and packaged skill; Turbo reuses unchanged outputs
```

`scripts/rea.mjs` imports `dist/cli-runtime/` or `dist/mcp/main.js`. Without
`dist/` it prints "REA's compiled runtime is missing" and exits `1`; a stale
`dist/` runs the previous code: rerun `npm run build:cached` after every source edit you want to observe.
Build commands hold checkout-local locks in `.cache/rea-command-locks/`; never
remove them while a command runs.

## One-shot CLI commands

`node scripts/rea.mjs <command> ... --json` is the `rea` binary from this
checkout. `--help` lists every command; `<command> --help` lists its options.

```sh
node scripts/rea.mjs --help
node scripts/rea.mjs providers --json
node scripts/rea.mjs analyze-javascript-application \
  "$PWD/tests/conformance/readiness/javascript-cli" \
  --detail summary --evidence_output "$DIR/app-evidence.json" --json \
  > "$DIR/summary.json" 2> "$DIR/progress.log"
```

The last command needs no native engine. Complete Evidence goes to the
`--evidence_output` file and stdout carries the summary view; summary delivery
requires that file. Without `--detail summary`, stdout carries the complete
Evidence, which is much larger. An existing `--evidence_output` file is
refused only after the analysis has run: exit `1`, code `invalid_request`,
with the complete Evidence inside the error's `details`.

- stdout carries the result or the structured error; progress (`rea_progress`
  JSON lines) and logs go to stderr. Redirect each to a file in `$DIR`.
- The default terminal format is TOON. `--json` is indented on a terminal and
  compact when piped.
- Exit status `0` means completed, possibly with partial Evidence; `1` means
  the operation failed, with a structured error; `128 + N` follows a signal.
  `setup` and `doctor` have their own rules in
  [docs/cli.md](../../../docs/cli.md#output-and-exit-status).
- REA reads and writes your configuration: `doctor` and `setup` read agent
  configuration, and a terminal run without `--json` or `--format` records an
  update check under `~/.cache/incur/updates/`. Those locations also follow
  `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR` and
  other agent variables, so a scratch `HOME` alone does not isolate a run.
  Start such commands with
  `env -i HOME="$DIR/home" PATH="$PATH" TERM="$TERM" node scripts/rea.mjs ...`,
  and pass provider variables such as `GHIDRA_INSTALL_DIR` explicitly.

Other commands that need no engine include `inspect-go-binary`,
`inspect-rust-binary`, `inspect-managed-artifact`, `inspect-model-artifact` and
`inspect-sqlite-database`; `analyze` on a directory or `.asar` takes the same
JavaScript path. `analyze`, `function` and `decompile` on a native binary need
a configured native provider; `providers --json` and `doctor --json` report
which are available and how to configure the rest. `doctor --json` exits `1`
while its scope is unhealthy, as on a host with no engine configured.

## Interactive setup

`rea setup` shows its planned changes and waits for approval before it writes
agent configuration or installs Hopper. Run it only in the isolated
environment above: first `setup --dry-run --json`, which returns `"status":"planned"` and exit
`0`, then the interactive form in tmux. Its first screen is a multi-select of
agents (`↑`/`↓` move, `Space` toggles, `Enter` confirms); with none detected it
lists every supported agent. `C-c` prints "Setup cancelled. No changes were
made." and exits `0`. `--yes` approves user-owned actions without prompting,
and `--accessible` asks the questions one at a time.

## MCP server

`node scripts/rea.mjs mcp` (also `npm start`) serves MCP on stdio as
newline-delimited JSON-RPC and exits `0` when stdin closes. Its stdout carries
only protocol messages; logs, when there are any, go to stderr.

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"rea-run","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node scripts/rea.mjs mcp > "$DIR/mcp.jsonl" 2> "$DIR/mcp.err"
node -e 'for (const line of require("fs").readFileSync(process.argv[1], "utf8").split("\n").filter(Boolean)) { const message = JSON.parse(line); if (message.id === 1) console.log(message.result.tools.length); }' "$DIR/mcp.jsonl"
```

The `tools/list` reply holds the complete catalog, several megabytes of JSON,
so count or select from it rather than printing it. Call `binary_session` with
`{}` for what is currently callable. `rea mcp doctor --json` checks production
MCP startup. `rea mcp --http --port N` serves one client over streamable HTTP
until SIGINT or SIGTERM and writes its bound URL to stderr; see
[transports](../../../docs/mcp-contracts.md#transports).

## Drive it in tmux

Use tmux for anything that prompts or keeps running: `rea setup`,
`rea mcp --http` and `environment-serve`. Give the run a private tmux server,
put the isolated environment in a script (a login shell rebuilds `PATH`), and
poll the screen after every step. Run this from the checkout root:

```sh
export TMUX_TMPDIR="$DIR"; unset TMUX
mkdir -p "$DIR/home"
cat > "$DIR/rea.sh" <<EOF
cd "$PWD" && exec env -i HOME="$DIR/home" PATH="$PATH" TERM="\$TERM" node scripts/rea.mjs "\$@"
EOF
screen_has() { # REGEX SECONDS: poll the pane until REGEX matches
  i=0
  while [ "$i" -lt $(($2 * 2)) ]; do
    tmux capture-pane -p -t rea | grep -qE -- "$1" && return 0
    sleep 0.5; i=$((i + 1))
  done
  return 1
}
tmux new-session -d -s rea -x 200 -y 50
tmux send-keys -t rea "sh $DIR/rea.sh setup; echo exit=\$?" Enter
screen_has 'Which agents should use REA' 60
tmux capture-pane -p -t rea > "$DIR/setup-screen.txt"
tmux send-keys -t rea C-c
screen_has '^exit=[0-9]' 30
tmux capture-pane -p -t rea > "$DIR/setup-cancelled.txt"
tmux kill-session -t rea
```

The typed command line stays on screen, so poll for text only the output
contains: `^exit=[0-9]`, not `exit=`. Send the next command only once the
previous one has printed its marker. The supermatt `qa` skill's
`scripts/tui.sh`, when installed, wraps these steps (`start`, `keys`, `wait`,
`stop`).

## Tests and checks

| Command                           | Use                                                                         |
| --------------------------------- | --------------------------------------------------------------------------- |
| `npm run test:local -- PATH...`   | Source tests without a build; no paths selects dirty files' tests           |
| `npm run test:focused -- PATH...` | Exact test files; boundary and acceptance paths build first                 |
| `npm run check:fast`              | Cached typecheck and lint; the pre-push check                               |
| `npm run format:check`            | oxfmt check of the whole tree; `npm run format` rewrites                    |
| `npm run docs:check`              | Generated documentation and README example consistency                      |
| `npm run check:pr`                | Optional complete local gate, including Python checks, docs:check and jscpd |

Select tests with [docs/testing.md](../../../docs/testing.md#choose-verification-for-the-change).
An empty selection means nothing ran, not that the change passed.

## Network

Needs network:

- `npm ci` (npm registry) and `npx rea-agents@latest`.
- `rea update`, and `rea setup --install-hopper`, which downloads Hopper.
- Browser and Electron commands reach whatever the observed page loads, and
  need a Chrome-family browser you supply; see
  [browser observation](../../../docs/browser-observation.md).
- Connections to engines you run yourself, such as an IDA or JEB MCP server.
- A terminal run without `--json` or `--format`, such as interactive
  `rea setup`, starts a detached check of the npm registry for a newer release
  at most once a day. `NO_UPDATE_NOTIFIER=1` or `CI=1` turns it off.

Works offline once dependencies are installed: `npm run build:cached`, static
inspection commands, `doctor`, `setup --dry-run`, `rea mcp` on stdio, and the
source test commands above.
