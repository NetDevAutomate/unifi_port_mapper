---
title: "Radio and WLAN Write-Path Correctness: Six Defects Found by Applying a Real Channel Plan"
date: 2026-08-03
category: analysis
tags: [radio, channel-optimiser, wlan, wpa3, port-overrides, api-persistence, 6ghz, dfs]
components: [analysis/channel_optimiser, analysis/radio_config, analysis/wlan_config, core/utils/errors]
problem_type: silent-data-corruption
severity: high
status: resolved
---

# Radio and WLAN Write-Path Correctness

## Table of Contents

- [Problem Statement](#problem-statement)
- [Defects](#defects)
  - [1. 6 GHz telemetry overwrote 5 GHz](#1-6-ghz-telemetry-overwrote-5-ghz)
  - [2. 80 MHz block collisions](#2-80-mhz-block-collisions)
  - [3. Load-blind 2.4 GHz channel pairing](#3-load-blind-24-ghz-channel-pairing)
  - [4. Non-atomic per-device radio writes](#4-non-atomic-per-device-radio-writes)
  - [5. Channel written as string is silently ignored](#5-channel-written-as-string-is-silently-ignored)
  - [6. ErrorCodes.NO_DATA never existed](#6-errorcodesno_data-never-existed)
- [The WLAN incident](#the-wlan-incident)
- [Rules that follow](#rules-that-follow)
- [Verification](#verification)

## Problem Statement

Applying a channel plan to a live 10-AP / 11-switch estate exposed six defects. Every one
of them was silent: the tooling reported success, the controller accepted the write, and
the resulting configuration was wrong. A separate WLAN change caused a partial outage.

The estate that surfaced these: seven U6 Pro, one U6 IW, one U6 LR, one U7 Pro XG Wall
(tri-band), controller 10.5.67.

## Defects

### 1. 6 GHz telemetry overwrote 5 GHz

`analyze_channels()` derived band from channel number:

```python
band = '5GHz' if ch > 14 else '2.4GHz'
```

A U7 Pro XG Wall reports its `6e` radio on **channel 37**. Both `na` (ch 36) and `6e`
(ch 37) therefore keyed into `ap_info['radios']['5GHz']`, and whichever came last won.
The reported "Office 5 GHz, 2% utilization" was 6 GHz telemetry, and the `na` channel
recommendation was computed from the wrong radio entirely.

A second copy of the same bug assigned `ht`: `band = '5GHz' if rid == 'na' else '2.4GHz'`
mapped `6e` to **2.4 GHz**, writing the 6 GHz radio's 320 MHz width onto the 2.4 GHz entry.

Fixed by `band_for_radio(radio_id, channel)`, which keys off the controller's radio id and
falls back to the channel heuristic only when the id is absent.

This matters more over time, not less: every tri-band AP added to a network makes the
misclassification more likely to be the one that gets acted on.

### 2. 80 MHz block collisions

`optimize_5ghz()` de-duplicated primary channels via a `used_channels` set. At 80 MHz the
four channels of a block are the same spectrum, so the optimiser proposed **149, 153 and
157** for three APs — total overlap, worse than the state it replaced.

Fixed with `block_80mhz()` and allocation over the six real blocks (36-48, 52-64, 100-112,
116-128, 132-144, 149-161).

The first fix was itself wrong. Sorting candidate blocks by score alone meant that once all
six were taken, every remaining AP chose the single cheapest block — on the live network
**ch116 was assigned to five APs**. Selection is now `(occupancy, score + committed_load)`,
which fills each block once before doubling up. A unit test alone would not have caught
this; it needed ten real APs against six blocks.

The optimiser also now keeps the current primary when the AP already sits in the winning
block, so 44 is not churned to 36 for zero gain.

### 3. Load-blind 2.4 GHz channel pairing

`optimize_24ghz()` scored channels from a static pre-computed average, so a channel did not
become more expensive after a busy AP was assigned to it. It placed the two busiest APs
(37 and 18 clients) on the same channel while a 3-client AP got one to itself.

Fixed with a running `assigned_load` term added to the score.

### 4. Non-atomic per-device radio writes

`apply_radio_config()` fetched devices once, then built every PUT payload from that same
cached device dict. Two changes to one AP — say `ng` width and `na` channel — meant the
second PUT carried the **original** `radio_table` and silently reverted the first.

Extracted `build_radio_table_updates()`, which merges all changes per device into one
payload and one PUT. Pure function, so the merge is unit-testable without a controller.

### 5. Channel written as string is silently ignored

The controller stores fixed channels as `int` (`Lounge na=60`, `Puzzle na=157`); only the
sentinel `'auto'` is a string. Writing `'149'` is accepted by the API and then ignored —
precisely the silent-no-op class this repo exists to detect. `build_radio_table_updates()`
now coerces `channel` to `int` unless it is a non-numeric sentinel.

### 6. ErrorCodes.NO_DATA never existed

`ErrorCodes.NO_DATA` was referenced by `config_drift`, `roaming_analysis`,
`neighbour_trend`, `link_error_tracking` and `latency_matrix` but was never defined on the
class. Every reference raised `AttributeError` instead of the intended `ToolError`, so each
module crashed on its own error path — `analyze roaming` with no baseline on disk produced
a traceback rather than "no baseline found".

Added the code, plus `tests/test_error_codes.py`, which scans the package for every
`ErrorCodes.X` reference and asserts it resolves. That prevents the whole class of defect
rather than this one instance.

## The WLAN incident

Two `minrate_*` fields needed changing on a 5 GHz WLAN. The change was made by fetching the
WLAN object, mutating two keys and PUTting the whole object back. Controller 10.5.67 ran
schema migration over the echoed object and changed four fields nobody asked for:

| Field | Before | After |
|---|---|---|
| `wlan_bands` | `['5g']` | `['5g', '6g']` |
| `wpa3_support` | `False` | `True` |
| `wpa3_transition` | `False` | `True` |
| `pmf_mode` | `disabled` | `optional` |

The causal chain: the PUT caused the controller to add the 6 GHz band; **6 GHz mandates
WPA3**; so WPA3 transition mode and PMF were enabled to satisfy it. WPA3 transition broke
association for the existing WPA2 clients, and roughly nine devices dropped off the 5 GHz
SSID and reattached to the 2.4 GHz IoT SSID. The 2.4-only WLAN was untouched because it has
no 6 GHz band to gain.

Diagnosis took two wrong turns first — DFS radar (disproved: all radios `state=RUN`, no
radar events) and the new rate floor (disproved: reverting it changed nothing). What
actually found it was diffing live state against the pre-change backup, which showed four
fields moving that were never in the patch.

A second trap sits next to it: `minrate_setting_preference` gates the manual rate fields.
Left at `'auto'`, the controller recomputes `minrate_*_data_rate_kbps` on provision and the
written value silently reverts. The first write attempt was lost exactly this way —
`bc_filter_enabled` persisted while both rate fields reverted.

`analysis/wlan_config.py` now provides the safe path: `update_wlan_settings()` sends a
minimal patch, re-reads, and asserts via `verify_wlan_patch()` that the patch applied *and*
that no guarded field moved. `check_minrate_gate()` warns when rate fields are patched
without the preference gate.

## Rules that follow

1. **Send minimal patches to `rest/wlanconf`.** Any field echoed back is a field the
   controller may migrate. Never round-trip a full WLAN object.
2. **Assert on guard fields after writing.** `WLAN_GUARD_FIELDS` covers WPA/PMF/bands/
   passphrase — drift in any of them can break an entire SSID's association.
3. **Match the controller's types.** A type mismatch is accepted and ignored, not rejected.
4. **Merge writes per device.** One PUT per device, never one per field.
5. **Derive band from the radio id, not the channel number.**
6. **Re-verify against a fresh read.** This controller reports success for writes it
   discards; the apply response proves nothing.
7. **Validate allocators against real inventory.** The ch116 five-way collision only
   appeared with ten live APs.

## Verification

- 1070 tests pass (32 new across three files), `ruff check` clean, `pyright src/` clean.
- Live confirmation after the fixes: the Office U7 Pro XG Wall reports its real 5 GHz radio
  (ch 36, not the `6e` radio's ch 37); a 10-AP plan spreads across all six 80 MHz blocks
  with at most two APs each; the two busiest 2.4 GHz radios no longer share a channel.
- `Unifi-5G` was restored from the pre-change backup and verified byte-identical (zero
  fields differing). The IoT rate-floor change was then re-applied as a partial patch with
  all six guard fields confirmed unchanged.
