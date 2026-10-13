# Circom Attack Vectors — Signal-flow & Field-arithmetic slice

Your slice of the catalog: categories **A (signal flow)** and **C (arithmetic / field)** — 10 vectors. Each vector is grounded in a real audit finding. Format: **D** defect / **FP** false-positive guard. Vectors are organized by **code shape** — the construct you grep for, not an abstract bug class.

Mantras for this slice:

- **Every `<--` is a constraint hole until proven otherwise.**
- **Every divisor in `<-- a/b` needs `IsZero(b).out === 0` upstream.**

---

## A. Signal flow

**V-A1. Assigned-but-unconstrained (`<--` without paired `===`)**

- **D:** A signal is computed via the witness-only operator `<--` but never tied back to the constraint system with `<==` / `===`. The R1CS therefore admits any field value for the signal and the prover wins. Especially dangerous when the RHS uses a non-quadratic op (`>>`, `<<`, `\`, `%`, `&`, `^`, `?:`), these cannot be expressed as a single quadratic constraint.
- **FP:** The signal is later pinned by a structurally parallel set of constraints — e.g. `q <-- a \ k; r <-- a % k; q*k + r === a; Num2Bits(log2(k))(r); LessThan(...)([r, k]).out === 1`. The pattern is "computed-then-bound", not "computed-then-used". The `out <-- 1/x; out * x === 1` inverse witness is sound when paired with `IsZero(x).out === 0`.

**V-A2. Output signal declared but never assigned**

- **D:** A `signal output Y` is declared but no `Y <==` or `=== Y` ever runs in the template body — typically because the assignment was commented out or replaced with an unrelated expression (variable-name typo). The R1CS compiles cleanly and the prover sets `Y` to any field element.
  - **Sub-pattern (variable-name typo on the recomposition target):** the final constraint accidentally references the input instead of the locally-recomposed sum, leaving the per-slot output free:

    ```circom
    // BinSum-style example, with the recomposition typo'd:
    for (var k = 0; k < nout; k++) {
        out[k] <-- (lin >> k) & 1;
        out[k] * (out[k] - 1) === 0;
        lout += out[k] * e2;
        e2 = e2 + e2;
    }
    lin === nout;   // BUG: should be `lin === lout`; out[] is unconstrained
    ```
- **FP:** `Y` is assigned via a sub-component output (`Y <== sub.out`) or inside a loop branch — both count. Witness mutation immediately exposes truly-free outputs.

**V-A3. Witness-only division paired with one polynomial check**

- **D:** Pattern `out <-- num/div; out * div === num` collapses to `0 === 0` whenever `div = 0`, leaving `out` free. Recurs across every Circom EC primitive that computes a slope as `<-- (Δy)/(Δx)` — e.g. Montgomery `λ <-- (y2-y1)/(x2-x1); λ * (x2-x1) === (y2-y1)`, and the Edwards-to-Montgomery / Montgomery-to-Edwards conversions. The divisor reaches zero on a degenerate point pair, point-at-infinity, or sentinel input; the slope then becomes a free variable and the EC operation is forged.
- **FP:** An explicit non-zero check on the divisor — `signal isz <== IsZero(div).out; isz === 0;` — or a hard-coded non-zero constant divisor (the `IsZero` template internally provides a non-zero witness, so its output `=== 0` is a valid guard); or the call is dispatched through a wrapper (`EllipticCurveAdd`) that detects degenerate inputs and routes to a doubling formula (see also V-C3).

**V-A4. XOR via `a + b - 2ab` without booleanity and recomposition**

- **D:** The identity `a + b - 2ab` computes XOR only when `a, b ∈ {0, 1}`. When the per-bit decomposition is written as `a_bits[i] <-- (a >> i) & 1` with the booleanity check (`a_bits[i] * (a_bits[i] - 1) === 0`) commented out, AND the recomposition (`Σ a_bits[i] * 2^i === a`) missing, the prover can pick arbitrary field values for `a_bits[i]` and forge any "xor" output.
- **FP:** Inputs are already provably boolean (output of an upstream `IsZero` / `IsEqual` / `Num2Bits` slot) AND the bits are recomposed back to the source: both legs are required if the bits feed an output sum.

**V-A5. Shift / rotation reconstructed from one linear identity in two free `<--` signals**

- **D:** A 32-bit rotation written as `signal part1 <-- (in << L) & 0xFFFFFFFF; signal part2 <-- in >> (32 - L); (part1 / 2**L) + (part2 * 2**(32-L)) === in;` is one linear equation in two free unknowns. The prover picks any `part2`, computes `part1 = 2^L * (in − part2 * 2^(32-L))`, and `out <== part1 + part2` is an arbitrary 33-bit value.
- **FP:** Both halves are individually width-bounded by tight `Num2Bits(L)(part2); Num2Bits(32-L)(part1);` calls upstream — the bit constraint pins each half uniquely.

---

## C. Arithmetic / field

**V-C1. Field-element overflow on narrow accumulator**

- **D:** A loop accumulating `acc[i] <== base * acc[i-1] + chunk[i]` followed by `acc[N-1] === in` is mod-p arithmetic, not over Z. When `log2(base) * N >= 248`, two distinct chunk vectors hash to the same field element (one canonical, one wrapping `+ p`). Same trap with `BigInt(==)` evaluated as a single accumulated `=== 0` over chunks.
- **FP:** The total bit width of the accumulation is provably `< 248` (assert it); each chunk is `Num2Bits(width)`-checked; or the equality is performed limb-by-limb after carry propagation rather than via a single accumulated comparison.

**V-C3. AddUnequal-style EC formula collapses on equal inputs / point-at-infinity**

- **D:** Any `EllipticCurveAddUnequal` formula (BLS12-381, BN254 Montgomery) keys a polynomial constraint on `(b - a)`. When `a == b` the polynomial reduces to `0 === 0` and the slope/output is unconstrained. Same shape with point-at-infinity inputs to non-affine adders, or aggregations whose all-zero participation bits produce `(0, 0)` instead of identity.
- **FP:** Caller dispatches through a safe wrapper that checks `IsEqual(a, b).out === 0` before the AddUnequal call (or routes equal-x inputs to a `Double` template); aggregator emits an explicit `is_infinity` output flag that callers must consume.

**V-C4. EC scalar `s = 0` accepted into curve multiplication**

- **D:** A scalar `s` feeding `s * T` (curve multiplier) without `IsZero(s).out === 0` collapses to identity for `s = 0`. In `EfficientECDSA`, `pubKey = s*T + U` then equals `U` for any chosen target `U`, forging signature verification.
- **FP:** Explicit `IsZero(s).out === 0`, plus a range check `BigLessThan(n, k)(s, q).out === 1` against the curve order; or the scalar is derived from a hashed message that the protocol proves non-zero by other means.

**V-C5. "Already reduced" / "no scaling required" comment with no constraint**

- **D:** Comments claiming a value is in canonical form, scaled, or pre-reduced rarely emit the matching constraint. When the surrounding code right-shifts by more bits than the value's intended width, the value is silently zeroed (panther `forTxReward` is shifted away by 60 bits when its bit-width is 40); when leaves are claimed representable in 254 bits but `p < 2^254`, some leaves are unrepresentable (completeness bug).
- **FP:** Cross-reference the comment with the surrounding `Num2Bits`/`Bits2Num` widths: if `bitwidth(value) <= shift_amount`, flag. If the comment is paired with an explicit `assert(bitwidth(value) > shift_amount)` or with a constraint-emitting scaling step, accept.

**V-C6. Accumulator sum overflows mod p before comparison or hashing**

- **D:** Chained sums `a + b + c ...` feeding a comparator or hasher without a bound on the total width: when individual operands are 250-bit values, two such sums overflow `p` and wrap. The comparator then mis-classifies, or the hasher collides on inputs that disagree only by a multiple of `p`.
- **FP:** Apply `Num2Bits(n)` to the *result* with `n` strictly less than `log2(p) ≈ 254`; or ensure operand bit-widths sum to `< 253` by static analysis.

---

Slice total: 10 vectors (A:5, C:5).
