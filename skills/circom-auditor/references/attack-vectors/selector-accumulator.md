# Circom Attack Vectors — Selector/mux & Accumulator slice

Your slice of the catalog: categories **D (selector / mux)** and **E (accumulator)** — 9 vectors. Each vector is grounded in a real audit finding. Format: **D** defect / **FP** false-positive guard. Vectors are organized by **code shape** — the construct you grep for, not an abstract bug class.

Mantras for this slice:

- **Every `Mux*` selector needs `s * (s - 1) === 0` upstream.**
- **`assert(...)` is not a constraint — it's a compile-time check the verifier never sees.**

---

## D. Selector / mux

**V-D1. Selector-as-enabler collapses the gated check**

- **D:** Pattern `signal x <== flag * (a + b); ForceLessEqThan(N).in[0] <== x;` (or `flag * hash === commitment`, or `enabled <== <witness-derived signal>`) is **not** "if flag then check" — it's "the disabled branch trivially satisfies the check at zero". Whenever `flag = 0`, both sides go to zero and the constraint is `0 === 0`. The author intended graceful disablement; the actual semantics are silent bypass.

  ```circom
  // panther: nullifier-verification-can-be-disabled
  zAccountUtxoInNullifierHasherProver.enabled <== zAccountUtxoInSpendPrivKey;
  // attacker sets spendPrivKey = 0 → ForceEqualIfEnabled disabled → any nullifier accepts
  ```

- **FP:** `flag` is hard-bounded by an upstream boolean constraint AND the disabled-branch outcome is the protocol-intended one (re-enforced via a `Mux1` to a known-canonical value); or the gating uses `ForceEqualIfEnabled` correctly with both branches independently constrained.

**V-D2. Merkle-path / mux selector not boolean-constrained**

- **D:** `MultiMux1(2)(c, indices[i])` computes `out = (c[1] - c[0]) * s + c[0]`. When `s` is not constrained to `{0, 1}`, the prover linearly interpolates between the two branches and forges any leaf at any path. Same trap with custom Merkle templates whose `path_index[i]` array is fed straight from `signal input` without `path_index[i] * (path_index[i] - 1) === 0`.
- **FP:** Selector is derived from another comparator's `.out` (already boolean), or `s * (s - 1) === 0` is enforced locally before the mux.

**V-D3. Array selector via `LessThan(idx, n)` instead of sum-of-equality**

- **D:** Array indexing gadgets that gate `out[i] = (idx == i) ? arr[i] : 0` via `LessThan(idx, n)` silently return all-zero output for out-of-range `idx` (or for `idx + p`-style aliases). Downstream "if out is zero, treat as default" logic accepts the invalid index.
- **FP:** Selector built as `out[i] <== IsEqual()([i, idx]).out * arr[i]` with `Σ IsEqual()([i, idx]).out === 1` enforced (exactly-one match).

**V-D4. Loop bound strictly less than tag/index domain**

- **D:** `assert(offset < 16)` followed by `for (var i = 0; i < 15; i++) { is_equal[i].in[1] <== offset; }` — the loop never visits `i = 15`, so `offset = 15` matches no iteration and the entire chained `enabled` accumulator stays at its initial value (often `0` or `1`), bypassing the inclusion check. Combine with V-D5 (assert-vs-constraint) for a complete bypass.
- **FP:** Loop bound covers the full domain of the index's tag/range (e.g. `for i < 16` for a 4-bit tag); or the index domain is hard-bounded by a `ForceLessThan(bits)` matching the loop bound.

**V-D5. `assert(...)` mistaken for a constraint**

- **D:** Circom's `assert` is a witness-generator-time check. It does **not** emit an R1CS constraint and is not enforced by the verifier. Common misuses: bounding offsets (`assert(offset < 16)`), validating padding bytes (`assert(eM[0] === 188)` for RSA-PSS 0xBC trailer), or anti-replay guards. The host prover crashes during witness generation if the assert fails honestly, but a malicious prover constructs a witness directly and bypasses the assert entirely.
- **FP:** Each `assert(...)` is paired with a real constraint gadget (`ForceLessThan`, `IsZero(...).out === 0`, `Num2Bits`, `===`) that mirrors the same predicate.

**V-D6. One-hot decoder without IsZero pairing**

- **D:** `out[i] <-- (inp == i) ? 1 : 0; out[i] * (inp - i) === 0;` is one-sided: the constraint forces `out[i] = 0` when `inp != i`, but the matching slot is never forced to `1`. The prover can set every `out[i] = 0` and `success = 0` to make the decoder accept any `inp`.
- **FP:** Replace the witness hint and one-sided constraint with `out[i] <== IsZero(inp - i).out;` — the IsZero template emits both directions.

**V-D7. Non-determinism / multiple valid witnesses for one public output**

- **D:** A template's public output can be produced by more than one witness assignment — typically because length / padding / leading-zero data can vary while hashing to the same digest. A nonce extractor that admits both `0x0001` and `0x000001` decodings produces distinct `packedNonce` values for the same JWT, breaking equality checks the host language relies on.
- **FP:** Length / offset signals are themselves public and bound to a unique canonicalisation; or a tight `Num2Bits` width prevents leading-zero / trailing-zero ambiguity. Picus-style determinism checks pass.

---

## E. Accumulator

**V-E1. Multiplicative accumulator seeded with input data instead of `1`**

- **D:** `product[0] <== element` instead of `product[0] <== 1` makes a set-membership product `Π (set[i] - element)` collapse to zero whenever `element = 0`, regardless of set contents. Generalisation: every iterated accumulator must seed with the algebraic identity for its operation (`*` → `1`, `+` → `0`, `XOR` → `0`).
- **FP:** Seed is the operation's identity element, or the accumulator carries a known-safe domain-separator value, and any seed that depends on input data is independently constrained.

**V-E2. Per-key accumulator filtered by the wrong side's key**

- **D:** Per-address-sum accumulator `Σ_{addr=k} amount[i]` keyed by the *input* address while aggregating the *output* side (or vice versa) lets one side smuggle entries past the equality check. Concretely: outflow ERC20 sum keyed by `spending_note_token_addr` instead of an outflow address admits any output-side entry whose token addr never appears in the input.
- **FP:** Filter key comes from the same side the accumulator aggregates; or the accumulator iterates over the union and rejects mis-matched-side entries explicitly.

---

Slice total: 9 vectors (D:7, E:2).
