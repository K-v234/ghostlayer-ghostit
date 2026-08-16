
# Ghost IT — Technical Debt Register



Real, honest list of known gaps and deferred work, each with why it's

deferred and what would trigger picking it up. Not a wishlist —

everything here was deliberately scoped out of finished work, not

forgotten.



## Real capability gaps (need new capture infrastructure, not wiring)



| Item | Why deferred | Trigger to revisit |

|---|---|---|

| JA4Fingerprinter (C14) | Needs raw TLS ClientHello byte capture -- no eBPF hook exists for this yet, and TLS record-layer parsing under the verifier's constraints is genuinely harder than DNS wire format was. Comparable in size to the DNS capture project, likely larger. | Real customer need for TLS-based C2 detection, or a dedicated session with fresh attention for the eBPF work |

| EmailPhishingDetector (C14) | Needs a full parsed email object (headers, body, attachments) -- requires mail server or email-client-level integration, a completely different data source than endpoint syscall telemetry. | Real customer need, or a decision to add mail-gateway integration as a product feature |

| T1105 Ingress Tool Transfer (MITRE gap) | Needs a `url` field -- confirmed absent from the entire event schema and Rust agent capture. | Same eBPF work as JA4/DoH's payload-capture needs -- could potentially piggyback on future network-payload capture work |

| T1110 Brute Force (MITRE gap) | Needs cross-event failure-count tracking (stateful, like IdentityDetector's `_last_login` dict) -- not built. | Real, contained addition -- lower effort than the above two, worth prioritizing first when this list gets picked up |



## Real refactor/hygiene work, correctly scoped out



| Item | Why deferred | Trigger to revisit |

|---|---|---|

| Full Evidence-type rename (11 detector classes) | **Investigated properly this session, concluded it does not apply.** Confirmed via grep: all 11 alert classes (LOLBinAlert, ExfiltrationAlert, IdentityAlert, MemoryExploitAlert, DNSAlert, DoHAlert, JA4Alert, EmailAlert x2, MitreDetection, RansomwareAlert) are referenced ONLY inside their own defining detector file plus the one immediate conversion point in engine.py -- zero references anywhere else in the codebase. They never reach the pipeline, dashboard, or API. The real unification this item was meant to achieve already exists: every wired detector's output gets converted into the shared `Detection` class (13 real call sites confirmed) at the exact point it becomes actionable, and `Detection` already carries `detection_method`/`schema_version`. Renaming these 11 internal-only, few-lines-of-lifetime dataclasses would be cosmetic-only -- same category of low-value work already correctly rejected elsewhere in this project (biological renaming, "Ghost Platform" rebrand). | None -- closed, not deferred |

| Detector Protocol/interface formalization | Investigated properly this session -- a single Protocol requiring one `check(event) -> Alert | None` method does not actually fit the real code. Several detectors have multiple distinct, non-interchangeable check methods (LOLBin: check_cmdline, check_process_chain, check_event; Identity: check_pass_the_hash, check_impossible_travel) -- forcing a single interface would mean meaningless wrapper methods or merging genuinely-different checks. **Downgraded from "todo" to "investigated, does not apply as originally scoped."** The real, already-consistent pattern across every detector: each check method returns `Optional[SomeAlertClass]` given event/specific-input, called explicitly by name inside engine.py's crash-sandboxed try blocks. That pattern is already the de facto contract; no code change adds real value here. | Revisit only if a future detector genuinely needs a single, swappable entry point (e.g. a plugin system) |

| Attack-surface folder regrouping (detectors/ organized by kill-chain stage instead of flat) | Purely organizational, zero functional value, "free if already touching the files" item that never lined up with a session that was touching all the files at once. | Opportunistic -- do it the next time multiple detector files are being edited together |

| Broader per-event/per-detector sandboxing (rest of run_once's 529-line loop) | Individual detector calls (8 of them) are now crash-sandboxed. The *rest* of the loop (event enrichment, PID cache, Cortex feeding, temporal memory, adaptive thresholds) still runs unprotected. Full per-event sandboxing would need extracting the loop body into its own function -- same re-indentation risk flagged and deferred for the original crash-sandboxing work. | A dedicated session, ideally with the loop-body extraction done as its own careful, verified step first |



## Week 3 ambient tasks (not started)



| Item | Status |

|---|---|

| Split `ghost_events`/`alerts`/`incidents` into separate tables with per-type retention | Not started |

| Grafana panels for MTTD and false-positive rate | Not started |

| Half-page principles addendum to SAD §31 | Not started |

| DuckDB migration trigger alerts wired into Grafana | Not started (numeric thresholds already defined in the base remediation plan) |

| Prometheus is sole metrics destination (not duplicated into ghost_events) | **Verified correct** -- confirmed via code review, only heartbeat_miss (a legitimate security event, not a metric) touches ghost_events |

| Parquet flush stays fully async under Redis Streams | **Verified correct** -- insert_batch only appends to in-memory _flush_pending; actual disk writes happen on a fully separate background thread |



## Explicitly rejected, not deferred (real reasons, not oversights)



Control plane, per-agent mTLS, tenant isolation, secrets manager, model registry, replay engine, feature/graph stores, HA/multi-region, agent/response SDKs, plugin marketplace, "Ghost Platform" rebrand, biological/organism renaming -- all evaluated and rejected as premature for a 3-person team with the current customer count. Each has a real trigger condition (second customer, team growth, a measured scale threshold) recorded in the base architecture remediation plan.




## Resolved this session



| Item | What was actually wrong | Fix |

|---|---|---|

| 60-day FP tracker | Genuinely dead, not just old: `daily_log.py` queried the lab VM's own local dashboard API (127.0.0.1:8001), which itself queried a local pipeline (127.0.0.1:8000) that no longer exists in the current multi-machine architecture. Both hops silently swallowed the resulting connection failures, producing a falsely-clean "0 alerts" for ~50 consecutive days rather than a visible error. `mark_fp.py` had also never actually been committed to this repo at all -- no way existed to record a real false positive even if one had been found. | Rebuilt `daily_log.py` to run directly on Lightsail, querying the real pipeline's `/alerts` endpoint with the real internal-auth secret (same pattern as `tests/regression_suite.py`) -- no intermediate hop. Grouped by `comm` instead of `type`, since every real alert now shares `type=="detection"`; the actual rule identity lives in `comm` as `detection:{rule_id}`. Wrote `mark_fp.py` from scratch, matching the exact JSON structure `report.py` already expected. Verified all three scripts together end-to-end with real data (59 real alerts, mostly from this session's own MITRE_T1110/LOLBin testing) plus a real mark-and-revert test of the FP-marking flow. New cron job registered on Lightsail (not the lab VM), start date reset to today since the prior ~50 days of "0 alerts" data was never real. |

