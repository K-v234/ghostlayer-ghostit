
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

| Full Evidence-type rename (11 detector classes -> one unified schema) | Originally scoped as the "big" Week 2 item; mapping the real blast radius showed 11 separate alert classes (LOLBinAlert, ExfiltrationAlert, IdentityAlert, MemoryExploitAlert, DNSAlert, DoHAlert, JA4Alert, EmailAlert x2, MitreDetection, RansomwareAlert), each different shapes and consumers. The evidence *principle* (detectors observe, confidence computed downstream) is already applied piecemeal via detection_method tagging and the Cortex split -- the full unifying rename is real but lower-urgency polish now that the principle is substantively in place. | A second detector-writing pass, or if inconsistent shapes actually cause a real bug |

| Detector Protocol/interface formalization | Detectors still have inconsistent method names (check_event, analyze, analyze_query, check_pass_the_hash) -- a shared Protocol/ABC would make this uniform. Real, but cosmetic -- doesn't change behavior. | Same session as the Evidence rename, since they're related |

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

