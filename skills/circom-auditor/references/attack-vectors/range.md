# Circom Attack Vectors — Range-check slice

Your slice of the catalog: category **B (range checks)** — 7 vectors. Each vector is grounded in a real audit finding. Format: **D** defect / **FP** false-positive guard. Vectors are organized by **code shape** — the construct you grep for, not an abstract bug class. This is the most prolific class of Circom soundness bugs in the wild.

Mantras for this slice:

- **Every `LessThan(N)` operand must come from a `Num2Bits(M ≤ N)` chain.**
- **Every `Num2Bits(254)` over BN254 needs `_strict` or an alias check.**

---

## B. Range checks

**V-B1. Comparator input not range-checked**

- **D:** `LessThan(N)` / `LessEqThan(N)` / `GreaterThan(N)` / `GreaterEqThan(N)` assume each operand fits in `N` bits. With un-range-checked inputs, the prover supplies values like `p − k` for small `k`; the internal `Num2Bits(N+1)` of `(1<<N) + a − b` accidentally fits in `N+1` bits but the unsigned ordering is wrong, and the comparator silently mis-classifies.
- **FP:** Operand comes from `Num2Bits(M ≤ N)` upstream, from another comparator's `out` (already in `{0,1}`), from an enforcing tag template (verify the tag actually constrains the range — see V-B6), or from a hash-derived input bound by a public commitment.

**V-B2. Comparator output instantiated but never consumed**

- **D:** A `LessThan` / `LessEqThan` / `IsEqual` / `IsZero` is wired up but its `.out` is never asserted (no `=== 1`, no `=== 0`, never fed to another component). The comparator's internal `Num2Bits` runs but its result is a dead constraint.
- **FP:** `.out` is consumed inside a non-trivial flag expression (`flag * lt.out` where the resulting flag is itself constrained). Comparator is intentionally instantiated only for its side-effect of bit-bounding the input; document this case explicitly.

**V-B3. `Num2Bits(254)` aliasing on BN254**

- **D:** Over BN254, `p ≈ 2^254 − δ`, so `Num2Bits(254)` accepts two distinct decompositions for any `x < 2^254 − p`: the canonical bits of `x`, and the bits of `x + p`. Whenever the bits feed a Merkle path, comparator, hash, or per-bit blacklist, the prover picks the alias that satisfies their goal.
- **FP:** `Num2Bits_strict()` (which bundles `AliasCheck` ensuring `< p`); `Num2Bits(N)` for `N ≤ 253`; an upstream guarantee that the input is already `< 2^253` (rare in practice — re-aliasing is the norm).

**V-B4. BigInt remainder per-limb-bounded but `< modulus` missing**

- **D:** Multi-limb modular reduction `r = a mod p` typically witnesses each `r[i]` and adds `Num2Bits(n)(r[i])`. The per-limb bound is necessary but not sufficient — without `BigLessThan(n, k)(r, p).out === 1`, the prover can submit any `r' = r + k·p` (for `k ≥ 1`) whose limbs still fit in `n` bits, breaking modular uniqueness.
- **FP:** `BigLessThan(n, k)(r, p).out === 1` (or equivalent comparator) follows the per-limb bounds; `BigEqual` against an already-reduced value folds in the bound; modulus is a compile-time constant whose limbs strictly exceed `r`'s.

**V-B5. PackBytes / BytesToField input bytes not range-checked**

- **D:** `PackBytes(k)` / `BytesToField(n)` / hand-rolled `Σ in[i] · 2^(8i)` assume each `in[i] ∈ [0, 256)`. Without `Num2Bits(8)(in[i])`, the map is multilinear: `[0, 1, 0]` and `[256, 0, 0]` pack identically, giving a trivial second-preimage on any downstream Poseidon commitment. Aliasing also lets a forbidden value (e.g. `IND` country code) be smuggled into a "not in list" check.
- **FP:** Inputs are bytes by construction — output of a regex DFA's `traversed_chars`, `Num2Bits(8)` already applied upstream, or sourced from an `AssertBytes` template.

**V-B6. Tag-issuing template missing its own constraint**

- **D:** Circom tags (`signal output {sub_order_bj_sf} out`) are an architectural promise that the issuer enforces an invariant `P` on the signal. When the body never actually asserts `P` (e.g. `BabyJubJubSubOrderTag` instantiates `LessThan(251)` but never `n2b.out === 1`), every downstream consumer that trusts the tag is misled.
- **FP:** Body terminates in the implied constraint — `Uint8Tag` body must include `Num2Bits(8)(in)`, `BinaryTag` body must include `(in - 1) * in === 0`, etc. Tag is purely informational and no consumer relies on it (rare; usually consumers deduplicate validation by trusting the tag).

**V-B7. Tag consumer fed a non-conforming value**

- **D:** A `BinaryTag(ACTIVE)(x)` requires `x ∈ {0, 1}`; feeding it `signedHash * (1 − isZeroDeposit.out)` (a 254-bit field element times a boolean) violates the tag's contract algebraically and the consumer's downstream `(1 - x) * y === 0` constraint becomes uncheckable for honest users (over-constraint, completeness break).
- **FP:** The expression handed to the tag is provably in the tag's domain: wrap unbounded factors in `IsNotZero()(hash)` first, or destructure the expression so each factor is individually constrained.

---

Slice total: 7 vectors (B:7).
