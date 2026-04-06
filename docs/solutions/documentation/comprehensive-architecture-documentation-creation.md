---
title: "Comprehensive Architecture and Operational Documentation for UniFi Management CLI"
date: 2026-04-06
category: documentation
tags: [documentation, architecture, c4, mermaid, plantuml, codemap, runbook, parallel-agents]
components: [docs]
problem_type: documentation-gap
severity: medium
status: resolved
---

# Comprehensive Architecture and Operational Documentation

## Table of Contents

- [Problem Statement](#problem-statement)
- [Solution](#solution)
  - [Approach](#approach)
  - [Documents Created](#documents-created)
  - [Key Decisions](#key-decisions)
- [Related Documentation](#related-documentation)
  - [Existing Docs Inventory](#existing-docs-inventory)
  - [Cross-Reference Opportunities](#cross-reference-opportunities)
  - [Remaining Gaps](#remaining-gaps)
- [Prevention and Best Practices](#prevention-and-best-practices)
  - [Documentation Maintenance Strategy](#documentation-maintenance-strategy)
  - [Documentation-as-Code Practices](#documentation-as-code-practices)
  - [Lessons Learned](#lessons-learned)
  - [Future Documentation Opportunities](#future-documentation-opportunities)

---

## Problem Statement

The UniFi Management CLI project had grown to 70+ Python source files across multiple subsystems (device management, MCP server, provisioning scripts, client libraries) with no accompanying architecture documentation. New contributors and returning maintainers faced a steep onboarding burden: there was no map of how modules related to each other, no explanation of the layered design, no canonical reference for CLI command syntax, and no runbook for diagnosing operational failures.

This mattered for two reasons. First, the project had non-trivial complexity -- a layered architecture spanning transport, client, service, and CLI concerns, plus an MCP server integration -- making intuition-driven navigation unreliable. Second, the absence of troubleshooting guides meant that operational incidents (device unreachable, auth failures, provisioning errors) required source-diving rather than following documented diagnostic paths. The gap created fragile institutional knowledge tied to a single developer's working memory rather than durable project artefacts.

---

## Solution

### Approach

The task required creating architecture documentation for a 70+ module Python project with no existing docs. The process ran in three phases:

**Phase 1 - Codebase Exploration**: Read key files directly (`typer_cli.py`, `network_cli.py`, `api_client.py`, `models.py`, `mcp/server.py`, `protect/client.py`, `config.py`, `pyproject.toml`, `README.md`) to build a complete mental model of the architecture before writing anything. This front-loaded the context so all five agents could work from verified facts rather than assumptions.

**Phase 2 - Parallel Agent Dispatch**: Five documentation-expert subagents ran concurrently, each receiving detailed prompts containing the full architectural context gathered in Phase 1. Parallelism cut total wall-clock time significantly; because each agent had its own clearly scoped document to produce, there were no conflicts.

**Phase 3 - Source Verification**: Each agent read actual source files to confirm command syntax, error messages, and API patterns. This caught real discrepancies -- for example, `stp optimize` defaults to `--dry-run` (not `--apply`), and MQTT topic structure came from `mqtt.py` directly rather than the README, which was out of date.

### Documents Created

| File | Lines | Key Content |
|------|-------|-------------|
| `docs/architecture/c4-architecture.md` | 1,130 | C4 Levels 1-4, both Mermaid and PlantUML renderings, class diagrams, exception hierarchy |
| `docs/architecture/architecture-overview.md` | 1,193 | 7-layer deep dive, 6 design patterns identified, 4 sequence diagrams, full dependency graph |
| `docs/architecture/codemap.md` | 1,163 | All 70+ modules mapped and described, 8 Mermaid diagrams, 3 workflow sequences |
| `docs/guides/use-cases-and-howto.md` | 1,666 | 10 real-world use cases, 21 diagrams, PlantUML actor diagrams |
| `docs/operations/troubleshooting-and-runbook.md` | 1,283 | Diagnostic flowcharts, ConnectionState FSM, full error reference, SOPs for common failure modes |

Total: approximately 6,400 lines across 5 files.

### Key Decisions

**Documentation-expert subagent type for all five agents.** This specialisation produces better document structure, logical flow between sections, and appropriate heading hierarchy compared to general-purpose agents.

**Full context in every agent prompt.** Rather than giving agents only file paths and telling them to explore, the exploration phase results were embedded directly in each prompt. This eliminated redundant file reading across agents and ensured consistent facts (module names, class names, CLI flag syntax) throughout all five documents.

**Mermaid AND PlantUML for C4 diagrams.** Different tooling ecosystems consume different formats. GitHub renders Mermaid natively; architecture tools like Structurizr and many enterprise diagramming tools consume PlantUML. Producing both formats makes the C4 document portable without requiring conversion later.

**Source-first verification over README trust.** The README described intended behaviour; the source described actual behaviour. Key discrepancies found: `stp optimize` defaults to dry-run mode (safety-critical distinction), MQTT topic hierarchy differs from README description, several CLI flags had undocumented aliases visible only in the typer decorators.

---

## Related Documentation

### Existing Docs Inventory

| Path | Type | Summary |
|------|------|---------|
| `docs/architecture/architecture-overview.md` | Architecture | 7-layer system architecture with Mermaid diagrams, design patterns, sequence diagrams |
| `docs/architecture/c4-architecture.md` | Architecture | C4 model (all 4 levels) with Mermaid and PlantUML |
| `docs/architecture/codemap.md` | Reference | Module-by-module reference for every file in `src/unifi_mapper/` |
| `docs/guides/use-cases-and-howto.md` | User Guide | 12-section practical how-to covering every major workflow |
| `docs/operations/troubleshooting-and-runbook.md` | Operations | 3-part runbook: troubleshooting, operational procedures, quick reference |
| `docs/mcp-server/MCP_SERVER_GUIDE.md` | Feature guide | Concise MCP server guide covering tech stack and tool categories |
| `docs/mcp-server/IMPLEMENTATION_PROMPT.md` | Design record | Original MCP server implementation prompt (design rationale) |
| `specs/architecture-and-codemap.md` | Superseded | Older architecture doc predating `docs/architecture/` |
| `specs/protect-control-plane.md` | API reference | OpenAPI reference for UniFi Protect API |
| `specs/network-control-plane.md` | API reference | Network control plane API reference |
| `specs/protect-integration-tasks.md` | Task list | Historical Protect integration task list |
| `specs/protect-monitor-guide.md` | Feature guide | Protect monitor documentation |
| `specs/rspan-limitations-and-removal.md` | Decision record | RSPAN limitations ADR |
| `README.md` | User-facing | Installation, CLI reference, device compatibility |

### Cross-Reference Opportunities

The following cross-links should be added to improve documentation navigation:

- **README.md** should link to `docs/architecture/architecture-overview.md`, `docs/guides/use-cases-and-howto.md`, and `docs/operations/troubleshooting-and-runbook.md`
- **architecture-overview.md** and **c4-architecture.md** should cross-reference each other (complementary views)
- **codemap.md** should link to architecture-overview.md for the design-pattern perspective
- **use-cases-and-howto.md** should link to the runbook for when workflows fail
- **troubleshooting-and-runbook.md** should link to use-cases for understanding intended workflows
- **docs/mcp-server/MCP_SERVER_GUIDE.md** should use relative links to `IMPLEMENTATION_PROMPT.md` and `codemap.md` Section 16
- **specs/architecture-and-codemap.md** should be archived or receive a deprecation notice pointing to new docs

### Remaining Gaps

1. **No AXIS provisioning documentation in `docs/`** -- README covers it but no dedicated guide exists
2. **No DHCP diagnostic documentation** -- brainstorm and plan exist but tool is not yet implemented
3. **`specs/` content is unlinked** -- API reference specs would be useful cross-references in architecture docs
4. **No testing documentation** -- test suite structure, patterns, and how to run specific categories
5. **No CHANGELOG or ADR directory** -- `specs/rspan-limitations-and-removal.md` is the only ADR-like document
6. **No auto-generated API reference** -- would require improved docstring coverage first

---

## Prevention and Best Practices

### Documentation Maintenance Strategy

#### When to Update Each Document

| Document | Update When | Trigger |
|----------|-------------|---------|
| **C4 Architecture** | New external integration, module boundary change, new CLI entry point | PR adds `src/` subdirectory or changes `pyproject.toml` entry points |
| **Architecture Overview** | New design pattern, material data flow change, dependency added/removed | PR description contains "refactor"/"redesign" or touches core layer |
| **Codemap** | New module added, public interface changes, module renamed/deleted | Any file change under `src/` beyond internal implementation |
| **Use Cases** | New CLI command, flag changes, workflow changes | Changes to `@app.command()` decorated functions |
| **Runbook** | Error messages change, new failure mode, prerequisites change | Changes to exception handling, logging strings, or tool metadata |

#### Review Cadence

| Cadence | Activity |
|---------|----------|
| Per PR | Author checks whether their change triggers a doc update; updates in same PR |
| Monthly | 15-minute sweep: run command examples from use-cases against live environment |
| Quarterly | Architecture review: do C4 diagrams still reflect reality? |
| Per release | Full codemap pass for modules added without docs; update changelog |

The most important rule: **documentation changes travel in the same PR as the code changes that make them stale.** A separate "docs cleanup" PR that lags by weeks is a documentation decay pattern, not a maintenance strategy.

### Documentation-as-Code Practices

**Mermaid as canonical diagram format.** Keep all diagrams in Mermaid syntax embedded in Markdown. Do not maintain exported PNG or SVG copies -- they drift. Mermaid renders natively on GitHub, VS Code, and JetBrains IDEs.

**Verify command examples against source on each release.** Run each CLI command's `--help` output and diff against doc examples. Consider capturing `--help` output to a fixture file in CI.

**CI checks for internal links.** Use `markdown-link-check` or `lychee` against `docs/` on every PR that touches Markdown files. Check internal links always; external links on a scheduled run only.

### Lessons Learned

**Parallel subagent dispatch works for independent documentation tasks.** The five documents have low interdependency. Each agent could read source independently and produce its artifact. The constraint: agents dispatched in parallel cannot reference each other's output. The mitigation -- providing shared architectural context upfront -- substitutes for cross-agent communication. When parallel dispatch breaks down: if Document A's conclusions should shape Document B's framing, serialize instead.

**Providing architectural context upfront produces better results.** Agents given file paths plus architectural framing produce documentation that explains the system. Agents given only file paths produce descriptions. The investment in writing the architectural briefing pays compound returns across all downstream agents.

**Having agents read source files for verification catches README drift.** Agents explicitly instructed to verify claims against source files flag discrepancies. Agents given only existing documentation faithfully reproduce whatever has drifted. The instruction pattern: "Read `src/X.py` and verify whether the usage example matches the actual function signature."

**The 5-document structure provides good coverage without over-engineering.** The combination covers four audiences: architect/contributor (C4 + overview), developer navigating code (codemap), user of the tool (use cases), operator handling failures (runbook). Anything beyond these five for a project of this size risks documentation nobody reads.

### Future Documentation Opportunities

1. **API Reference Docs** -- Auto-generate with `pdoc` or Sphinx once docstring coverage reaches ~60% of public functions. Start with CLI command handlers and service layer.
2. **Contributing Guide** -- Needed when first external contributor appears. Cover: dev environment setup with `uv`, test suite, PR process, coding conventions.
3. **Changelog** -- Maintain `CHANGELOG.md` using Keep a Changelog format once the project has users beyond the author. Update `[Unreleased]` in same PR as every user-facing change.
4. **Integration Test Documentation** -- Document test environment requirements separately from the runbook: UniFi OS version, device types, network topology assumptions.
