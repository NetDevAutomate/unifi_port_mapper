---
title: "Port Label Drift: Stale Labels as False Evidence, and the Guards a Refresh Needs"
date: 2026-08-03
category: analysis
tags: [port-naming, lldp, port-overrides, diagnostics, false-evidence]
components: [analysis/port_naming, typer_cli, run_methods]
problem_type: stale-configuration
severity: medium
status: resolved
---

# Port Label Drift

## Table of Contents

- [Problem Statement](#problem-statement)
- [Why the existing discover path missed it](#why-the-existing-discover-path-missed-it)
- [Naming precedence](#naming-precedence)
- [The four guards](#the-four-guards)
- [What is deliberately not touched](#what-is-deliberately-not-touched)
- [Relationship to run_methods](#relationship-to-run_methods)
- [Verification](#verification)

## Problem Statement

An audit of an 11-switch estate found port labels that no longer described what was
plugged in:

- `Office USW Ultra 210W` p1-p7 read the factory default `PoE Out + Data`. They were seven
  named access points.
- `Lounge USW Flex 2.5G 8 PoE` p1 and p2 had their two downstream switches **transposed**.
- `Lounge USW Flex 2.5G 8 PoE` p3 read `axis-b8a44f9f0228`. It was the uplink to a switch;
  the camera of that name was on a different switch entirely.
- `Office Window USW Flex 2.5G 5` p4 read `pi5`. It was a JetKVM. The actual Raspberry Pi
  was on another switch.

Stale labels are worse than missing ones, because they get used as evidence. Two
diagnoses during the same session were wrong because of these:

1. "Two AXIS cameras are on faulty cabling — an identical camera on another switch
   negotiates 2500 Mbps with zero errors." That 2500 Mbps port was a **switch uplink**
   mislabelled with a camera's name. The control case did not exist; all three cameras are
   100 Mbps by design.
2. "A Raspberry Pi 5 is stuck at 100 Mbps, which is the same cable-fault signature." The
   port labelled `pi5` was a JetKVM, a 100 Mbps device. The real pi5 was healthy at
   1000 Mbps.

Both retractions trace to trusting a label instead of the live client and LLDP tables.

## Why the existing discover path missed it

`run_methods._choose_port_name` resolves an LLDP peer from `remote_device_name` /
`system_name` / `chassis_name`. UniFi access points populate **none** of these. With no
usable LLDP name and no matching wired client (an adopted AP is not a client), the function
fell through to "port is up and the current name is not `Port N`, so keep it" — which is
exactly how `PoE Out + Data` survived every previous refresh.

`analysis/port_naming.resolve_peer()` resolves the LLDP `chassis_id` against the
adopted-device registry instead. That single change recovered the seven AP labels and
corrected the three transposed or misattributed switch links.

## Naming precedence

1. LLDP peer resolving to an adopted UniFi device -> its name, plus the remote port id when
   that id is not itself a MAC (`Shed USW Flex XG 10G te1`).
2. Exactly one wired client -> that client's name.
3. Several wired clients -> `<best name> +N`.
4. Otherwise leave the label alone.

## The four guards

Each was added after observing the naive version produce a worse label against live data.

| Guard | Observed failure |
|---|---|
| `would_lose_information` | `Google Streamer 4K` -> `b4:23:a2:af:9b:3f`, because that client momentarily reported no hostname. A placeholder may be replaced by an address; a real name may not. |
| `name_quality` | `Office-Apple-TV` -> `42:ed:cf:6f:ff:35 +2` on a three-client port, because a raw MAC sorts first alphabetically. Ranks hostname > vendor string > address. |
| `is_cosmetic_change` | `AI-Port` -> `AI Port`: a write, a provision cycle, and no information gained. |
| `strip_multi_suffix` | `ax-b8a44f283f3d +1` <-> `ax-b8a44f283f3d` flipping on every run, because a Synology appears and disappears between polls. |

`is_placeholder_name` is also a superset of the legacy `_is_default_port_name`: it treats
`PoE Out + Data`, `PoE In + Data` and `SFP …` as placeholders, not just `Port N`. It
deliberately does **not** treat `Port 7 Media Rack` as one.

## What is deliberately not touched

- **Down ports.** A disconnected port's label is frequently the only record of what used to
  be plugged into it.
- **Non-switch devices.** The gateway is excluded; its WAN port labels are not derived from
  client data.
- **Other port overrides.** Writes go through `update_port_names`, which merges into the
  existing `port_overrides` entry per port, so `poe_mode`, `port_profile` and speed
  overrides survive. Replacing `port_overrides` wholesale would silently drop them.

## Relationship to run_methods

`run_methods._choose_port_name` is **left unchanged**, and the duplication of three small
predicates is accepted on purpose.

Swapping the broader `is_placeholder_name` into the legacy path would change its behaviour
at the "keep the current name" branch: `PoE Out + Data` would stop being retained, and
because that path cannot resolve AP peers it would rename those ports to `Port N` — a
regression in `discover` traded for three deduplicated predicates. Consolidating `discover`
onto this module is viable but needs its own verification pass, so it is deferred rather
than bundled here.

## Verification

- 22 unit tests, one per guard plus peer resolution, placeholder recognition and scope.
- 1092 tests pass overall; `ruff check` and `pyright src/` clean.
- Live round-trip on a real switch: `Office USW Lite 8 PoE` p3 was set to `Port 3`,
  `ports refresh` detected the drift and proposed `MacMiniM4` from wired-client data,
  `--apply` restored it, and a re-run reported no changes needed. Confirms detection,
  application, convergence and idempotency against the controller.
- Before productising, the ad-hoc version converged 32 ports across 10 switches; the
  module independently agrees that estate now needs no changes.
