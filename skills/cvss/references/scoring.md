# CVSS scoring reference

Sources: [FIRST v4.0 specification](https://www.first.org/cvss/v4.0/specification-document), [v4.0 user guide](https://www.first.org/cvss/v4.0/user-guide), [v4.0 calculator](https://www.first.org/cvss/calculator/v4.0), [v3.1 specification](https://www.first.org/cvss/v3.1/specification-document), [v3.1 calculator](https://www.first.org/cvss/calculator/3.1).

## Procedure

1. Use the version requested by the caller or already present in the advisory. For a new assessment with no requested version, prefer v4.0. Do not compare scores across versions as if their metric definitions were identical.
2. Write down the exact vulnerable component and attack scenario. Separate conditions intrinsic to exploitation from deployment assumptions; verify privileges and user interaction from the actual path.
3. For v4.0 Base, choose AV (Attack Vector), AC (Attack Complexity), AT (Attack Requirements), PR (Privileges Required), UI (User Interaction), impacts on the Vulnerable System (VC, VI, VA), and impacts on Subsequent Systems (SC, SI, SA). Distinguish a required external condition (AT) from exploit difficulty (AC). Do not assume downstream impact without a demonstrated boundary crossing.
4. Set Threat (E) or Environmental (CR, IR, AR and modified Base metrics) only when the relevant exploit intelligence or deployment facts are known. Supplemental metrics provide context but do not change the score. Label the result CVSS-B, CVSS-BT, CVSS-BE, or CVSS-BTE as appropriate.
5. Enter the full vector in the matching FIRST calculator and report its score and qualitative rating. Include the vector so the result can be reproduced. Do not invent a numeric score from a severity word or calculate v4.0 by applying the v3.1 formula.

For v3.1, assess AV, AC, PR, UI, Scope (S), and Confidentiality/Integrity/Availability (C, I, A) with the v3.1 definitions. Keep v3.1 and v4.0 vectors distinct.

CVSS Base scores measure severity of the vulnerability, not the likelihood or business risk of a particular deployment. A published NVD or GHSA score may use different assumptions or a different version; show both sources and explain the difference rather than silently replacing one.
