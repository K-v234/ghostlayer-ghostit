
# Ghost IT — Disaster Recovery: Real RTO/RPO



Status as of Aug 8, 2026 (Day 5 hardening). These are measured numbers

from real incidents and real tests this session, not estimates.



## RPO (Recovery Point Objective) — how much data can be lost



| Failure type | RPO | Mechanism |

|---|---|---|

| Container crash / process death | **0 events** | Hot buffer WAL (R-04) — proven via real `docker kill` test, 1/1 events recovered, EVENT_SEQ correctly advanced |

| Full server loss (Lightsail instance) | **≤ 6 hours** | Automated local backup every 6h (cron on Lightsail), plus automated off-site pull every 6h (cron on local dev machine). Both directions proven working today with real transferred, verified archives (193 files, tar -tzf confirmed). |



## RTO (Recovery Time Objective) — how long to get back up



| Scenario | RTO | Basis |

|---|---|---|

| Container restart (crash, OOM, etc.) | **~10 seconds** | Measured today: docker kill -> up -> healthy, WAL recovery included |

| Full pipeline rebuild from git (code-level) | **~15-20 minutes** | Based on actual rebuild+redeploy cycles performed multiple times this session |

| Full server rebuild from scratch | **Not yet measured on this exact stack** | Prior sessions report full VM/server recovery achieved twice historically, but not timed under today's current TLS+auth+WAL+backup configuration. |



## What's proven today, with real tests



- Hot buffer survives a crash — real kill, real recovery, real event count verification

- EVENT_SEQ survives a restart without resetting — verified twice

- Local backup produces a valid, restorable archive (193 files, tar -tzf verified)

- SSH key auth set up from scratch (previously only browser-console access existed)

- Off-site backup pull proven end-to-end: real 50MB archive transferred from Lightsail to local machine, verified intact

- Both backup directions (local cron on Lightsail, pull cron on local machine) scheduled every 6 hours



## Remaining real gap



- No restore *drill* has been run — we've proven the backup archive is valid and listable and transferable, not that a full restore-from-backup actually brings the running system back up end-to-end. That's the next real test to run, not a documentation task.

- Full-server-rebuild RTO not re-timed against today's hardened configuration.




## Deployment log



**2026-08-09** — Lab VM (192.168.154.129) agent deployed with all

Week 1/2 work to date: DNS capture (real eBPF sendmsg hook), Identity

detector, 7 MITRE gap detectors, MemoryExploit, DoH, LOLBin confidence

fix. Also closed a real gap found during this deployment: the lab

VM's agent had been running on plain TCP port 9000 since Day 1's TLS

work was built -- never actually switched over. Now on port 9443

with TLS, confirmed via "Connected to pipeline" log line and real

event flow (total climbed from 4.58M to 5.33M+ within minutes of

restart). Old binary/BPF object backed up to

/opt/ghostit/backup-20260809/ on the lab VM before the swap.

