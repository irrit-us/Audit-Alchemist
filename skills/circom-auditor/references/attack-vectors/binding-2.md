# Circom Attack Vectors — Protocol-binding slice II (signatures, merkle, sponge, format)

Your slice of the catalog: category **H (protocol binding)**, part 2 of 2 — vectors **H9–H16** (8 vectors). These cover signature-gadget preconditions, affine ECDSA, merkle/SMT construction footguns, Poseidon/sponge collisions, inter-circuit and circuit↔host format mismatches, liveness/DoS via prover-controlled commitments, and compiler/parameter footguns. Part 1 (replay, nullifiers, public inputs, privacy) is the `binding-1` slice. Format: **D** defect / **FP** false-positive guard. Organized by **code shape**.

Mantra for this slice:

- **A signature/merkle gadget enforces only what its body constrains — every precondition (on-curve, in-subgroup, `< order`, fixed depth, domain tag) is the caller's job until proven otherwise.**

---

## H. Protocol binding (H9–H16)

**V-H9. Affine relation with free precomputed points and no message binding**

- **D:** An "efficient ECDSA" circuit accepts precomputed points `T`, `U` as private inputs and only checks `pubKey = s*T + U` (an affine relation). Without per-point constraints tying `T` and `U` to the message and randomness (`U = -m * r^-1 * G`, `T = r^-1 * R`), the prover treats `(T, U, s)` as three free variables and solves for any target `pubKey` in the membership tree.
- **FP:** Expose `m` and the signature components publicly; constrain each precomputed point against the message inside the circuit; or reject the "efficient" gadget in favour of a direct EC scalar-mult formulation.

**V-H10. Replicated intermediate with `_temp` / `_final` / `_intermediate` suffix confusion**

- **D:** Two intermediate signals differ only by a `_temp` / `_final` suffix (e.g. `drv_mGrY[j].xout` vs `drv_mGrY_final[j].xout`). A consumer references the wrong stage — typically the pre-padding intermediate when the post-padding one was intended — and the resulting ciphertext / commitment is computed from stale data. Mechanical bug, easy to grep, easy to miss in review.
- **FP:** Mechanical rename + grep audit: every consumer of `_temp` is independently justified, every consumer of `_final` is justified. Pair-suffix suspicion is itself a flag.

**V-H11. Signature gadget precondition not enforced at call site**

- **D:** EdDSA / BLS / ECDSA verifier gadgets accept (`pubKey`, `message`, `signature`) without checking on-curve, in-subgroup, less-than-curve-order, less-than-modulus. Caller assumes the gadget enforces these; gadget assumes the caller does. Examples: `R8X, R8Y` not `BabyCheck`'d before `EdDSAPoseidonVerifier`; `r, s` not in `[1, n-1]` for ECDSA; signature limbs not range-checked against modulus; suborder tag not actually enforcing `< suborder`.
- **FP:** Each canonical precondition is enforced at the boundary: `BabyCheck()(R8X, R8Y)`, `BigLessThan(...)(r, n).out === 1`, `BigLessThan(...)(s, n).out === 1`, suborder reduction. Or the precondition is provably inherited from upstream (signature was just hashed from a trusted source).

**V-H12. Domain-separation / variable-length Poseidon collisions**

- **D:** Poseidon used over variable-length input without folding the length and a domain tag into the capacity / state hashes the same digest for `[a, b, 0]` and `[a, b]`, or for two protocol-distinct messages with the same field elements. Pattern: any `PoseidonFieldArray` / hand-rolled Merkle-Damgård chaining over Poseidon, or `SpongeHash` that doesn't follow the SAFE API padding rules.
- **FP:** `PoseidonEx(t, capacity)` with `initialState = DOMAIN_TAG | length`; or the SAFE API. Length is part of the public input set and committed by the verifier.

**V-H13. Merkle construction footguns (depth, intermediate-as-leaf, truncated leaves)**

- **D:** Cluster of Merkle-tree implementation bugs that don't fit V-D2 / V-H3 / V-E1: (a) branch length not validated against the fixed tree depth — `restoreMerkleRoot` accepts forged inclusion at the wrong depth; (b) `MerkleRootCalculator` accepts an intermediate node as a leaf because no leaf-vs-node distinguisher is enforced; (c) SMT stores 64-bit truncated hashes — collision risk at 2^32 leaves; (d) generic length / depth fields not bound to the tree contract.
- **FP:** Tree depth is a compile-time parameter and `assert(depth == MAX_DEPTH)`; leaf hashes carry a domain tag distinguishing them from internal nodes; SMT uses full-width digests.

**V-H14. Inter-circuit / circuit ↔ host data-format mismatch**

- **D:** A public input that is computed off-circuit, consumed by a different circuit, or returned to/from Solidity has a precise byte/bit format. When the two ends disagree — `data[SUM_FIELD_COUNT]` interpreted differently in `ProveReputation` vs `UserStateTransition`, or `ZSwap.sol` skipping a deposit transfer the circuit assumed happened, or the circuit trusting the prover's `start_offset` for public-key location — a soundness or correctness bug appears at the boundary.
- **FP:** Both ends share a generated specification or a property-tested binding; format invariants are documented and tested with fuzz/randomised inputs.

**V-H15. Liveness / DoS via prover-controlled commitment data**

- **D:** A multi-step protocol where step `N`'s output commitment is computed by the prover and consumed in step `N+1`. A malicious step-`N` prover commits to ill-formed data (BigInts whose limbs exceed `2^n`, sync-committee aggregates with `(0,0)` "infinity" pubkeys, 96-bit caps applied to 112-bit products) that satisfies step-N constraints by accident but provably cannot satisfy any honest step-`N+1` proof. Honest provers in subsequent rounds are bricked.
- **FP:** Every commitment-input limb is `Num2Bits(n)` checked at step `N`; aggregator outputs an explicit `is_infinity` / `is_well_formed` flag that downstream rounds consume; comparator widths conservatively dominate every reachable product width.

**V-H16. Compiler / parameter footguns (hardcoded array sizes, implicit parameter relations)**

- **D:** Circom helpers with hardcoded array dimensions (`bigInt[50]`) silently overflow when called with `k > 50`; templates with implicit parameter relations (`BigMult` assumes `k ≤ 2^n`; `Split`/`SplitThree` assume `n + m + k < 254`; `ModSumFour` requires `n + 3 ≤ 253`) emit no compile-time check and produce silently-wrong constraints when violated. `SSZLayer` silently no-ops for `numBytes < 64`.
- **FP:** Top-of-template `assert(k < 50)` / `assert(n + m + k < 254)` block making implicit relations explicit; treat hardcoded magic numbers (50, 32, 512, 254) as audit flags whose surrounding parameter relations must be documented.

---

Slice total: 8 vectors (H9–H16).
