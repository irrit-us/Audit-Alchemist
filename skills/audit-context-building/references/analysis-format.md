# Compact context record

Use only as much of this format as the target needs. Each claim should cite an observed source line; do not fill slots with guesses. `nothing found` means an enforcement search was attempted and its scope is recorded, not that the property is globally absent.

```text
Area: target path(s), source revision or snapshot, and inspected scope
Entries: entry point -> reachable actor -> trust boundary
State: durable values, owners, writers, and lifecycle

Function: path:line and name
Inputs: parameters, implicit state, caller identity, environment; trust level
Requires: each precondition -> establishing line/callee, nothing found, or open question
Effects: return values, writes, calls, emitted events; success and error paths
Guarantees: property -> line/path that establishes it
Dependencies: callee -> exact behavior assumed -> paths inspected
Callers: who uses each guarantee, including alternate branches
Open questions: claim not yet established -> next bounded check
```

## Review sequence

1. Orient from build metadata and relevant entry points. Identify the few functions on the requested path where external input, state, or authorization changes hands.
2. Read each function's implementation and relevant caller/callee. Trace outputs and out-parameters through early return, error, panic, and conditional paths. Include persistent-state and cross-request effects where applicable.
3. For each precondition, locate the actual check or state transition that establishes it. If unavailable, record the missing evidence and what was searched. Distinguish external black-box behavior from verified internal behavior.
4. Reconcile disagreements between records by rereading source; leave an unresolved conflict as an open question. Keep the index short and fetch detailed lines again before final citation.

An assumption with `nothing found` is a lead for later investigation. It becomes a reportable finding only after the ordinary audit establishes attacker control, reachability, failed protections, and consequence.
