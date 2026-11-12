# REA

REA (Reverse Engineer Anything) investigates local binaries, applications,
pages and runtime behavior for an analyst or an agent. The same application
workflows serve the CLI and the MCP server, and every answer carries the
Evidence, coverage and unknowns behind it.

## Language

### Targets and engines

**Target**:
The local file, directory, application, page or process a caller asks REA to investigate.
_Avoid_: sample, input, app (when the kind matters)

**Artifact**:
A concrete file or container REA inspects, identified by its content digest independently of where it was observed.
_Avoid_: blob, binary (for non-executables)

**Engine**:
A third-party analysis program, such as Hopper, Ghidra, IDA or JADX, that REA drives but never installs unasked.
_Avoid_: backend, disassembler (as the general word)

**Provider**:
The REA adapter, with a stable ID, that runs one engine or built-in analyzer and is named in every Evidence record it produces.
_Avoid_: plugin, integration, tool (for the adapter)

**Analysis session**:
One provider bound to exactly one parsed artifact, from `open_binary` until an explicit switch or `close_binary`.
_Avoid_: project, database, connection

**Analysis profile**:
The canonical commitment to a provider's identity and its analysis-affecting settings; it is part of an Evidence record's identity.
_Avoid_: options, config

**Function**:
A native code routine at an address that a provider identifies; `analyze_function` returns its function dossier.
_Avoid_: procedure, subroutine (except in existing contract fields such as `procedure_address`)

**Function dossier**:
The complete analysis of one function, with each facet's availability declared separately.
_Avoid_: function report

**Admission**:
The check that accepts a target or input within its format, authority and resource limits before any costly work starts.
_Avoid_: validation (when the budget is the point), preflight

**Owned process**:
A child process REA started and can still identify through its process supervisor; a PID and executable path alone do not prove ownership.
_Avoid_: managed process, child (when ownership matters)

### Evidence

**Evidence**:
The canonical, content-addressed record of one successful observation: subject artifact, provider, operation, parameters, results, confidence, authority, limitations and source locations.
_Avoid_: result, output, report (for the record itself)

**Confidence**:
How an Evidence result was reached: `observed`, `derived` or `inferred`.
_Avoid_: certainty, score

**Authority**:
The kind of source behind Evidence: `shipped-artifact`, `controlled-replay`, `historical-reference`, `external-service` or `analyst-inference`.
_Avoid_: trust level, source type

**Coverage**:
What part of the requested scope an answer actually examined; missing coverage is `unknown`, never absence.
_Avoid_: completeness (alone)

**Relationship coverage**:
The coverage of a provider's observed caller and callee set for a function, not of every possible runtime edge.
_Avoid_: call graph completeness

**Residual unknown**:
A durable, revisioned record of one unresolved or evidence-qualified question, with the authority and confidence its answer needs and the probes that could resolve it.
_Avoid_: gap, TODO, open question

**Probe**:
A suggested follow-up observation that could resolve an unknown or extend coverage.
_Avoid_: next step, hint

**Evidence bundle**:
A sealed, authenticated set of Evidence records, and the residual unknown histories that cite them, for export, transfer or comparison; record order has no meaning.
_Avoid_: dump, archive, export

**Retained Evidence**:
Evidence an MCP connection keeps so later views and workflows can cite it by ID without repeating analysis.
_Avoid_: cached result, history

**Analysis view**:
Derived Evidence that projects one parent Evidence record into a summary, a page or another view kind through `inspect_analysis_view`.
_Avoid_: report, filter, query result

**Analysis snapshot**:
A local file of successful analysis results that REA replays only when the target bytes, operation, parameters, provider and analysis profile match exactly.
_Avoid_: cache file, project file

### Tools and workflows

**Analyst question**:
The concrete question a caller is trying to answer; tools are designed around it rather than around an engine's API.
_Avoid_: use case, feature request

**Tool catalog**:
The complete canonical set of MCP tools that `tools/list` returns, including tools unavailable for the current target or provider.
_Avoid_: tool list, registry

**Primitive**:
A tool that reports one reusable fact about an identified object or relationship.
_Avoid_: low-level tool

**Workflow**:
A tool that composes primitives for a recurring multi-source outcome without hiding caller choices or uncertainty.
_Avoid_: pipeline, macro

### Runtime capture and agent environments

**Capture**:
Evidence recorded from runtime behavior, such as a browser page, an Electron app, a process or saved network traffic.
_Avoid_: recording, log, trace (a trace is a relationship query)

**Scenario**:
A declared sequence of actions REA runs against a browser, Electron app or process it launched, while capturing the results.
_Avoid_: script, test, playbook

**Environment manifest**:
An analysis view of one retained HAR capture that turns its recorded request lines into a replayable tool surface.
_Avoid_: API spec, mock definition

**Agent environment**:
An MCP server REA serves from an environment manifest and its capture, answering from what the capture observed without contacting the recorded application.
_Avoid_: mock server, sandbox

**Environment bundle**:
The folder `rea environment-export` writes so the agentenv framework can build and run an agent environment.
_Avoid_: package, image

### Reconstruction

**Reconstruction**:
A re-implementation of a target's behavior in source code, checked against the Evidence of the original.
_Avoid_: clone, port, decompilation (the provider's output, not the rewrite)

**Reference source**:
An older source tree imported as historical reference only, to compare with the current artifact.
_Avoid_: original source, ground truth

**Reconstruction obligation ledger**:
A deterministic list of claims a reconstruction must satisfy, derived from authenticated Evidence; an obligation closes only with a passing verifier of comparable authority.
_Avoid_: checklist, test plan

### Setup

**Client**:
An agent application, such as Claude Code, Codex or Cursor, whose configuration `rea setup` registers REA with.
_Avoid_: host, integration (user-facing text says "agent")

**Registration**:
The client configuration entry that launches `rea mcp`; `rea doctor` reports its state, such as aligned, stale or missing.
_Avoid_: install, config entry

**Packaged skill**:
The `reverse-engineer-anything` instructions that setup installs beside a registration, authored in `.agents/skills/reverse-engineer-anything/`.
_Avoid_: prompt, plugin

## Relationships

- An **Analysis session** binds one **Provider** to one **Artifact**; a **Provider** runs one **Engine** or a built-in analyzer.
- Every **Evidence** record names one **Provider** and at most one subject **Artifact**, and carries one **Confidence** and one **Authority**.
- An **Analysis view** is **Evidence** derived from exactly one parent **Evidence** record.
- An **Evidence bundle** holds many **Evidence** records and the **Residual unknowns** that cite them.
- An **Analysis snapshot** is bound to one **Provider**, one **Analysis profile** and one target identity.
- An **Environment manifest** is a view of one HAR **Capture**; an **Agent environment** serves one manifest with that capture.
- A **Reconstruction obligation ledger** is built from an **Evidence bundle** and closes obligations only with verifier **Evidence**.
