
# Ghost IT — Engineering Principles



**Status:** Intended as an addendum to SAD §31 (Companion to SAD v1.0)

**Length:** Half-page, deliberately not a new document — see base

remediation plan Problem 12: "the real ones worth writing down,

not a new 40-page constitution."



Every principle below is grounded in a real decision or a real bug

found during this build, not written in the abstract. Where a

principle was violated and caught, that's noted too — principles

earn their place by having actually mattered at least once.



---



### 1. Detectors observe. A separate layer decides.



Detectors (LOLBin, Identity, MITRE gap checks, JA4, DNS, DoH) return

evidence — a severity, a confidence, a reason. They never decide what

to *do* about it. That decision lives in `causal-engine/decision.py`,

split out specifically so a detector's own bug can't also corrupt

the decision logic that acts on other detectors' findings.



*Real example:* `JA4Fingerprinter`'s DoH-resolver check was firing

HIGH severity on nearly all normal HTTPS traffic — a real detector

bug. Because detection and decision are separate, disabling that one

check didn't touch decision logic, C2's Isolation Forest, or any

other detector at all.



### 2. AI advises. Deterministic policy decides.



This system has exactly two real learned models: Isolation Forest

(C2 behavioral) and GraphSAGE (C4 causal). Everything else that looks

like "AI" — Story Generator, JA4 fingerprinting, DGA detection — is

deterministic pattern-matching, not a model, and is tagged as such

(`detection_method` field, added specifically to make this

distinction visible in every alert rather than left implicit).



The autonomous-response engine runs in simulation mode by default.

No learned model's output ever directly triggers an action — it

always passes through Safety Governor and world-model blast-radius

checks first.



### 3. Fail closed on capture, fail open on action.



If a detector crashes mid-check, the event is *not* silently

dropped — the crash is logged and the loop continues to the next

detector (real crash sandboxing, added after finding zero protection

existed across 8 real detector call sites). But if an autonomous

response *decision* fails or times out, it does not default to

taking action — it defaults to logging and queuing, never acting on

an uncertain read.



### 4. A stuck connection must fail loudly, not silently.



Real bug this build found: neither TCP connect nor write anywhere in

the agent's pipeline-forwarding path had a timeout. A hung write

under real backpressure blocked forwarding indefinitely, with zero

log output — the code path that would have logged the failure never

ran, because the `.await` itself never resolved. Every network call

in that path now has an explicit timeout and an explicit failure

log, on the theory that a visible failure is always better than a

silent stall, however "small" the individual call looks.



### 5. Don't build the abstraction before the second real need.



Rejected or deferred, each for a stated reason, not by default:

control plane, per-agent mTLS, tenant isolation, model registry,

plugin marketplace, hot/warm/cold storage tiers. The DuckDB migration

trigger (this document's own companion metric work) is the pattern

to copy: a real, numeric threshold decides *when* an abstraction

earns its complexity, not a guess about "eventually."



---



*Real events referenced above (crash sandboxing, the pipeline

timeout fix, the JA4 DoH bug, detection_method tagging) are each

documented in full in git history and docs/TECHNICAL_DEBT.md. This

addendum names the pattern; those commits are the receipts.*

