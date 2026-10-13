# Circom Attack Vectors — Protocol-binding slice I (replay, nullifiers, public inputs, privacy)

Your slice of the catalog: category **H (protocol binding)**, part 1 of 2 — vectors **H1–H8** (8 vectors). These cover the gap between *what the protocol intends a proof to mean* and *what the circuit actually pins down*: replay, unbound public inputs, sentinel leaves, disabled verifiers, low-entropy nullifiers, and privacy leaks. Part 2 (signatures, merkle, sponge, format) is the `binding-2` slice. Format: **D** defect / **FP** false-positive guard. Organized by **code shape**.

Mantra for this slice:

- **Every public input must appear in at least one `===` / `<==` constraint.**

---

## H. Protocol binding (H1–H8)

**V-H1. Proof not bound to caller intent**

- **D:** A nullifier-burning / state-mutating verifier exposes only protocol-state public inputs (`pubRoot`, `pubNullifierHash`, `pubCreditType`) and no caller-controlled binding (`msg.sender`, intent hash, transaction nonce). An observer of the mempool re-broadcasts the proof from their own address, burning the nullifier and stealing the funds.
- **FP:** A `pubIntentHash` (or `pubReceiver`, `pubCallData`) public input is constrained inside the circuit and bound to caller-controllable context on-chain (e.g. `keccak256(msg.sender, callData)` mirrored as the public input).

**V-H2. Static issuer commitment omits per-action variable**

- **D:** A Poseidon commitment `H(sig[0..2])` computed identically across all actions of one issuer is constant per issuer. Deanonymising one token deanonymises every other — privacy leak by linkability.
- **FP:** Commitment binds a per-action variable (`tokenId`, `epoch`, `slot`) that is publicly exposed: `Poseidon(4)(sig[0], sig[1], sig[2], tokenId)`.

**V-H3. Sentinel zero leaf admitted as valid membership proof**

- **D:** Merkle-tree templates that use `zeroValue` for empty leaves but never assert `leaf != zeroValue` admit anyone whose identity-commitment hashes to the sentinel as an unremovable group member. With Semaphore's empty-tree zero, computing `Poseidon(Poseidon(n, t)) == zeroValue` brute-force grants universal membership.
- **FP:** Explicit `IsEqual()([leaf, zeroValue]).out === 0` in the membership circuit. Or the tree uses a non-cryptographic distinguishing value for empty leaves (e.g. domain-tagged sentinel that can never collide with a valid commitment).

**V-H4. Public input declared but never constrained**

- **D:** A `signal input` listed in `public [...]` (or top-level `main` declaration) that never appears on either side of `===` / `<==` / `<--` is a free public variable. The prover proves any value; the verifier accepts any value. Particularly insidious when the host language (Solidity / `verifier.sol`) trusts the public input and the linear "dummy use" is optimised away by `circom -O2`.
- **FP:** Public input appears in at least one non-linear constraint (`signal dummy <== x * x;` is the canonical anti-`-O2` pattern). Or public input is folded into a hash whose digest is independently constrained (`Poseidon(pub, secret)`).

**V-H5. Verifier gadget toggle hard-coded to `0`**

- **D:** Circomlib gadgets (`EdDSAPoseidonVerifier`, `ForceEqualIfEnabled`, `BabyCheck`) take an `enabled` toggle. Hard-coding `eddsa.enabled <== 0` turns off the entire signature check while leaving the gadget visually present in the source. Pattern: any imported verifier with an `enabled` set to a constant zero or a witness-derived signal that can be zeroed.
- **FP:** `enabled <== 1` for security-critical checks; or `enabled` is bound to a publicly-committed flag whose zero-branch is independently re-enforced (V-D1).

**V-H6. Low-entropy / non-context-binding nullifier**

- **D:** A nullifier `H(privKey)` (or `H(name, DOB, last4)`) without a per-action / per-context binding lets an identity holder re-register after small mutations (case, ordering, initials) — Sybil. In Panther's case, the renewal nullifier `H(privKey, commitment)` is replayable when `commitment` doesn't bind `privKey` to the public identity. Generalisation: nullifier preimage must include high-entropy per-context data plus a `privKey ↔ pubKey` consistency proof.
- **FP:** Nullifier is `H(s, ctx)` with `ctx` publicly committed AND a `BabyPbk(s).Ax === pubKey[0]; BabyPbk(s).Ay === pubKey[1];` consistency constraint. Or per-token / per-epoch normalisation hashes high-entropy fields.

**V-H7. Time-bound credential fed only into a hash, never compared**

- **D:** A signal named `*Timestamp` / `*Expiry` / `*Time` that is folded into a Poseidon hash but never compared (`LessThan`, `LessEqThan`, `ForceLessThan`) against current block time / chain header timestamp. The prover produces an indistinguishable proof for an expired credential.
- **FP:** `kycSignedMessageTimestamp + kycExpiryPeriod >= spendTime` (or `<= currentBlockTime`) enforced via `GreaterEqThan` / `ForceLessThan`; the comparator's input is range-checked (V-B1).

**V-H8. Privacy leak via comparison constraint not fully gated by privacy flag**

- **D:** `LessEqThan(252)([statementValue, sourceValue]).out === 1` is an unconditional inequality, while a paired `(statementValue - sourceValue) * statementComparator === 0` equality is gated by a privacy flag. When the protocol advertises an "anonymous mode", the always-on inequality leaks `sourceValue >= statementValue` even when comparison is supposedly disabled.
- **FP:** Multiply the residue `(leq.out - 1)` by the enable flag so the inequality also becomes a no-op when disabled; or collapse equality and inequality into a single `Mux1`-gated branch where the disabled output is a known canonical value.

---

Slice total: 8 vectors (H1–H8).
