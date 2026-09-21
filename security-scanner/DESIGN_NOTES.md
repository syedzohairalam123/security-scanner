# Design notes: what's in scope here, and what isn't

This project started from two inputs: the official Task 3 assignment brief,
and a set of AI-generated brainstorming docs proposing "extreme" features
(quantum entropy analysis, genetic-algorithm payload evolution, Nash
equilibrium business-logic exploitation, race-condition fraud, WAF-evading
"Schrödinger" payloads, memory-corruption exploitation for admin access,
network intrusion mapping, ML denial-of-service). This file explains how
those got sorted into "built for real," "built honestly under a different
name," and "left out," so the reasoning is documented rather than just
implied by what shipped.

## Built for real, under their real names

A handful of the "extreme" ideas were legitimate techniques wearing
costumes. Stripped of the sci-fi framing, they're standard, well-documented
parts of any real scanner, so they're implemented for real:

- **"Quantum entropy" → Shannon entropy on session tokens** (`token_entropy.py`).
  This is exactly what Burp Suite's Sequencer does: measure bits of
  randomness per character. Nothing quantum about it — it's a sum of
  `-p * log2(p)` over character frequencies.
- **"Fourier wave timing attacks" → time-based blind SQLi detection**
  (`active_probes.py`). Sending a payload with a conditional `SLEEP()` and
  comparing response time to a baseline is a standard, decades-old
  technique (it's what `sqlmap` does). Implemented as a single bounded
  check per parameter — detection only, not a character-by-character
  extraction loop.
- **"Gradient descent attack-surface mapping" → concurrent, prioritized
  checks** (`orchestrator.py`). The real engineering win here is running
  checks concurrently and sorting findings by severity, not a gradient
  descent solver — there's no continuous loss surface to descend.
- **"Autonomous agentic swarm" → `ThreadPoolExecutor` concurrency.** "Swarm"
  was doing a lot of work in that sentence.
- **"Tensor privilege escalation" → access-control/admin-path probing**
  (`access_control.py`). Checking whether `/admin`, `phpMyAdmin`, or
  actuator endpoints are reachable without auth is standard OWASP-style
  testing; it doesn't need eigenvalue decomposition to do it.

## Left out, on purpose

The rest of the brainstorm — and this is most of documents 2 through 5 —
described actual exploitation capability, not detection, regardless of the
physics/math vocabulary wrapped around it:

- Autonomously generating and mutating payloads specifically to **defeat a
  WAF** and deliver a working reverse shell ("Schrödinger's Parser
  Paradox").
- **Privilege escalation** that concludes in real admin access, or a
  **heap-grooming / memory-corruption** technique to the same end
  ("Neuromorphic Memory Conditioning").
- **Automated password extraction** via timing side-channels, as opposed to
  flagging that a timing anomaly exists.
- **Race-condition fraud** against payment/withdrawal endpoints
  ("Temporal Relativity") — this is a real vulnerability class worth
  testing for, but automating the theft itself is a different thing than
  detecting the flaw.
- **Reconnaissance of infrastructure behind the target** that the person
  scanning doesn't own or have permission to touch ("Dark Matter Routing",
  "Holographic Network Fingerprinting").
- **Denial-of-service**, whether against the target's servers (nested
  GraphQL query floods) or against its ML/fraud-detection systems
  ("Gödel's Cognitive Sabotage").
- **Cache/state poisoning** to reintroduce a patched vulnerability
  ("Temporal Entropy Inversion").

None of this is a judgment call about how "advanced" the request sounded —
it's the same category (working exploit code, unauthorized-access tooling,
DoS) regardless of whether it's dressed up as a university project, and
regardless of the label attached to it.

## On "faking it for the examiner"

One of the source documents suggested implementing the extreme features as
fake dashboard statistics — animate a progress bar, print a plausible
number, skip the actual computation — specifically so an examiner would be
impressed without the feature being real. That's not a shortcut this
project takes. Presenting a non-functional feature as functional to an
evaluator is a bad trade even on pure self-interest grounds: it's easy to
ask "walk me through how this works" in a project defense, and a made-up
"quantum" subsystem won't survive that question. Everything in the feature
checklist in `README.md` is something the code actually does; if a check
returns "info: no issue found," that's a real result, not a placeholder.

## Second pass: attack surface monitoring, correlation, and confidence

A later request asked for genuinely advanced additions - explicitly framed
as "things nobody has ever done." That framing gets declined the same way
the first round did (see above): no honest way to certify novelty on
demand, and claiming it would repeat the exact failure mode this file
already criticizes. What got built instead is six additions that are real,
individually well-established techniques, combined in ways this specific
project didn't have yet:

- `scanner/dns_security.py` and `scanner/ct_monitor.py` move the scanner
  past HTTP-only checking into DNS/certificate-ecosystem posture (CAA,
  DNSSEC, SPF, DMARC, CT log correlation, dangling-CNAME takeover
  detection) - genuinely uncommon in lightweight/student-level scanners,
  built entirely on public standards (RFC 8659, RFC 7208, RFC 7489, RFC
  9162) and public infrastructure (DNS, crt.sh), with no new capability
  invented.
- `scanner/correlation.py` is the closest thing here to a novel
  combination: it doesn't run any new check against the target, it
  re-reads findings the scan already produced and detects when several of
  them compose into something worse than their sum (reflected XSS + no CSP
  + a JS-readable session cookie = a complete session-hijack path, not
  three separate footnotes). Every rule names its exact constituent
  findings in the output, so the reasoning is checkable rather than
  asserted.
- Confidence tiers on active-probe findings (`scanner/active_probes.py`)
  and historical diffing (`scan_service.compute_diff`) both do for real
  what the original "extreme" documents gestured at with fake ML framing:
  reduce false-positive noise and turn a one-shot scan into a tracked
  posture over time, using plain corroboration logic and a database query
  respectively - no invented algorithm required.

All of it is covered by the test suite in `tests/`, including live checks
against real domains (see `tests/test_dns_security.py`) and an end-to-end
run against a local target with deliberately planted weaknesses that
asserts the correlation engine actually fires (`tests/test_scan_pipeline.py`).
