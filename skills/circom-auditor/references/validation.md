# Validate a Circom candidate

Use these checks in the order that best fits the candidate; stop when a concrete enforcing constraint refutes it. Do not promote a lead because several heuristics agree or because a witness path is merely plausible.

1. **Scope and intent.** Identify the entry template, included components, field/compiler settings, public inputs, and intended property from caller code or protocol documentation. Separate application assumptions from constraints enforced by the verifier.
2. **Control and reachability.** Show which private inputs, witness signals, public inputs, or external integration values an attacker can choose. Trace from that control point through every relevant assignment, constraint, component boundary, and verifier use. Inspect alternate branches and special values such as zero and field boundaries.
3. **Constraint satisfaction.** Demonstrate a specific bad witness satisfying the full constraint system while violating the intended property, or a valid honest input for which the circuit cannot produce a proof. If a constraint, range check, or guard pins the disputed value, reject the candidate. A witness-generator assertion or ordinary successful witness does not prove verifier enforcement.
4. **Consequence.** Establish a soundness, completeness, or privacy effect in the actual protocol. Check on-chain or host verifier binding where relevant. A code smell, unconsumed value, or weakened gadget with no reachable adverse effect is not a confirmed vulnerability.
5. **Evidence.** Cite exact inspected source lines. When possible, compile the affected circuit, inspect constraints, or run a focused positive/negative PoC. Record the command, compiler/library version, input, and observed result; do not claim a PoC passed when it was not run. Recheck any prior report against the current source.

The harness accepts only its existing validated JSON findings. Keep unresolved hypotheses in scratch notes if useful, then omit them from final findings. Do not copy the upstream report's confidence arithmetic, automatic lead-promotion rules, or agent provenance fields into the audit result.
