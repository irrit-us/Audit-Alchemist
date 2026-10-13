# Circom vector catalog

The six slices below preserve zkSecurity's 48 upstream example patterns and false-positive cues. Load only slices that match the target's code and threat model. They are historical candidate patterns, not rules that every circuit must implement exactly. Verify compiler version, field, library implementation, reachable call sites, and the complete emitted constraints before using an example as evidence. Some upstream examples rely on a particular BN254 field, Circom library, or application design.

| Target construct | Resource |
| --- | --- |
| Witness-only assignments, decomposition, field arithmetic, inverse and EC operations | `references/attack-vectors/signal-field.md` |
| Comparators, bit bounds, byte packing, tags | `references/attack-vectors/range.md` |
| Conditional checks, selectors, muxes, accumulators | `references/attack-vectors/selector-accumulator.md` |
| Public inputs, intent, replay, nullifiers, privacy | `references/attack-vectors/binding-1.md` |
| Signature, Merkle, hash, cross-template binding | `references/attack-vectors/binding-2.md` |
| Regex, encodings, Circom language behavior | `references/attack-vectors/regex-language.md` |

`D` describes a possible defect shape; `FP` suggests a possible guard. Neither establishes a finding or a refutation by itself. Follow `references/validation.md` for the evidence required by this harness. In particular, a name, comment, `assert`, or successful witness generation cannot replace an R1CS constraint. A missing textual `Num2Bits` or `===` in one file does not prove that the required property is absent from an included template or caller.
