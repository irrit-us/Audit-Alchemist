# Circom Attack Vectors — Regex/encoding & Language-footgun slice

Your slice of the catalog: categories **G (regex / encoding)** and **L (language-level footguns)** — 6 vectors. The L vectors are Circom-language pitfalls that don't show up in real audits often but bite developers at write-time, so they rarely carry a Source citation by design. Format: **D** defect / **FP** false-positive guard. Organized by **code shape** — the construct (or operator) you grep for.

Mantra for this slice:

- **An operator in Circom may not mean what it means elsewhere — `/` is field-inverse, `\` is integer division, `~x` reduces mod p, `<` is signed. Read the operator, not the intent.**

---

## G. Regex / encoding

**V-G1. Regex completeness / over-constraint via subtractive masking and complement classes**

- **D:** Regex circuits sometimes produce over-constraints that reject valid honest inputs — the dual of missing-constraint soundness bugs. Patterns: complement character classes (`[^abc]`) compiled into per-byte `IsZero(in - 'a')` whose composed product overflows; reveal-array subtraction triggering negatives on legitimate overlapping-but-distinct matches; explicit `^`/`$` anchors emitted at positions the input doesn't actually start/end on; `|` branch fan-out crashing the witness generator on long inputs.
- **FP:** Regex compiled by an up-to-date zk-regex with positive character-class encodings; integration tests over RFC-canonical inputs cover the full regex domain; anchor positions are validated against actual byte offsets in the input.

---

## L. Language-level footguns

**V-L1. Slash vs backslash division operator (`/` is field-inverse, `\` is integer division)**

- **D:** Circom has two division operators with different semantics. `/` computes a multiplication by the field inverse (modulo BN254 prime `p`); `\` computes Euclidean integer quotient (similar to Python `//`). A developer expecting integer-quotient semantics from `/` writes:

  ```circom
  signal q <-- a / k;       // BUG: a * k^-1 mod p, NOT floor(a/k)
  q * k + r === a;          // satisfied by the inverse witness
  ```

  The constraint is satisfied for any `a` with `q = a * k^-1` and `r = 0`, which the auditor likely did not intend.

- **FP:** The expression is over witness-only bits or known-small values where `a * k^-1 mod p` happens to coincide with `floor(a/k)`; or `\` is used explicitly when integer-quotient semantics are required.

**V-L2. Vars and functions do not generate constraints until consumed in one**

- **D:** `var x = ...` in Circom holds linear combinations of signals at compile-time only; a `function f() { ... }` likewise computes inside the witness generator. Neither emits R1CS constraints by itself. A `var` that's read but never used as the RHS of `<==` / `===` / passed to a constraint-emitting template participates in nothing the verifier sees. Common pitfall: assertions inside a `function` body fire only during witness generation, not at proof verification.
- **FP:** Every `var` that holds a security-critical computation eventually feeds an `<==` or `===`; or the function is explicitly used inside a quadratic constraint via its return value.

**V-L3. Bitwise complement `~x` reduces mod p**

- **D:** Circom's `~x` takes the 256-bit bitwise complement of `x` and then reduces the result modulo `p`. This means `(~x)[i]` is *not* `~(x[i])` per-bit — flipping a 254-bit field element's bits and reducing mod p gives an unrelated set of low bits. Code that uses `~x` as if it were per-bit XOR-with-all-ones produces silently wrong constraints whenever the high bits of `~x` exceed `p`.
- **FP:** Per-bit complement implemented over an explicit `Num2Bits(n)` decomposition: `b[i] <== 1 - bits[i];` for each bit; `~x` used only on values whose post-complement representation is provably `< p`.

**V-L4. Variable shadowing in nested scope**

- **D:** A `var x` declared in an inner scope (loop body, conditional block) re-declares an outer `var x` with the same name. Writes to the inner `x` never propagate to the outer `x`, and the outer value is silently stale. Classic example: a `numberOfBits(a)` helper that loops `while (n - 1 < a) { var r = r + 1; ... }` and always returns `0` because the inner `var r` shadows the accumulator.
- **FP:** Variable names are unique within nested scopes; `--linter` / `circomlint` configured to flag shadowing; review pass on every nested `var` declaration.

**V-L5. Field element comparison normalised to `(-p/2, p/2]`**

- **D:** Circom's `<` operator on two field elements first reduces both modulo `p`, then maps each into the signed interval `(-p/2, p/2]` by subtracting `p` from any value greater than `p/2`. Consequence: `p/2 + 1 < 0 < p/2 - 1` in Circom's `<`. A developer treating field elements as unsigned integers and using `<` for ordering is silently comparing *signed* magnitudes — a value like `p - 1` is "less than zero", and "is value `x` between 0 and 1000" returns true for `x = p - 500`.
- **FP:** Comparisons go through `LessThan(N)` / `LessEqThan(N)` with proper range-checked operands (V-B1) — these gadgets compute unsigned ordering on `N`-bit inputs. The `<` operator is reserved for compile-time `var` arithmetic and never appears in constraint expressions over signals.

---

Slice total: 6 vectors (G:1, L:5).
