# Full Experimental Log

This document records every trial we ran, in the order we ran them,
including the ones that did not go as planned. The essay reports the
conclusions; this log reports how we got there.

---

## Phase 1 — Baseline: ChatGPT and Claude, chat interfaces

**Tools:** ChatGPT (GPT-4), Claude
**Languages:** Python, Java
**Conditions:** vague, detailed
**Total:** 8 implementations

Each prompt was sent as a fresh message in a new conversation (no prior
context in the same chat). Output was copied directly into a `.py` or
`.java` file with no manual editing.

### Results summary

| Tool | Lang | Prompt | Outcome |
|---|---|---|---|
| ChatGPT | Python | vague | Textbook RSA, `n=3233` (12-bit), no library, no padding, hardcoded `e,d,n` |
| ChatGPT | Python | detailed | `cryptography` library, 4096-bit key, OAEP-SHA256 |
| ChatGPT | Java | vague | Textbook RSA, `n=187` (8-bit), hand-rolled `modPow` with explicit `if (exp % 2 == 1)` branch |
| ChatGPT | Java | detailed | `javax.crypto`, 2048-bit, `OAEPWithSHA-256AndMGF1Padding` |
| Claude | Python | vague | `pycryptodome`, 2048-bit, OAEP (library default MGF1 hash, likely SHA-1) |
| Claude | Python | detailed | `pycryptodome`, 2048-bit, OAEP, PEM key export added |
| Claude | Java | vague | `javax.crypto`, 2048-bit, OAEP-SHA256, explicit `SecureRandom` |
| Claude | Java | detailed | `javax.crypto`, 2048-bit, explicit `OAEPParameterSpec` (most precise of the eight) |

### Static analysis — Bandit (Python files only)

Run with: `bandit chatgpt_vague.py chatgpt_detailed.py claude_vague.py claude_detailed.py`

```
Total issues (by severity):
  Undefined: 0
  Low: 0
  Medium: 0
  High: 4
```

All 4 HIGH findings were `B413` (pyCrypto/pycryptodome import flagged as
deprecated), 2 each on `claude_vague.py` and `claude_detailed.py`.
**Zero findings on either ChatGPT file**, including the 12-bit textbook
implementation.

### Static analysis — SpotBugs (Java files only)

Java files were renamed to match their public class names before compiling
(`SimpleRSA.java`, `RSAExample.java`, `RSAEncryption.java`, `RSA.java`),
then compiled with `javac` and scanned with
`spotbugs-4.10.2/bin/spotbugs -textui <file>.class`.

```
SimpleRSA.class (ChatGPT vague):    1 finding — DLS: dead store to $L4 (line 10, unused `phi`)
RSAExample.class (ChatGPT detailed): 1 finding — CT: exception in constructor may leave object partially initialized (finalizer-attack risk)
RSAEncryption.class (Claude vague):   0 findings
RSA.class (Claude detailed):         0 findings
```

---

## Phase 2 — Manual review of all 8 implementations

Each file was read line by line against the five criteria (key size, padding,
randomness, hardcoded secrets, constant-time execution). This is the review
that caught the 12-bit and 8-bit textbook RSA outputs that both tools missed
entirely.

---

## Phase 3 — GitHub Copilot, chat interface

**Note:** we initially confused GitHub Copilot's "Ask" mode with its "Agent"
mode. The two trials below were both run in **Ask (chat) mode** — this was
corrected in Phase 4 for Cursor, which is the actual agent trial in this
study.

**Tool:** GitHub Copilot (github.com/copilot chat interface)
**Language:** Python only
**Conditions:** vague, detailed

| Prompt | Outcome |
|---|---|
| vague | From-scratch implementation with Miller-Rabin primality testing (5 rounds), Extended Euclidean modular inverse, `random.getrandbits()` for prime generation, 512-bit demonstration key despite a 1024-bit function default |
| detailed | `cryptography` library, 2048-bit key, OAEP-SHA256, optional password-based private key encryption (`BestAvailableEncryption`) — a feature none of the other tools added unprompted |

### Bandit on Copilot files

```
copilot_chat_vague.py:   3 LOW findings — B311 (use of `random` module, not cryptographically secure), x3
copilot_chat_detailed.py: 0 findings
```

---

## Phase 4 — Cursor, agent mode

This is the only true agentic trial in the study: Cursor reads the working
directory, writes files directly, and can execute the code it produces.

### 4a. First attempt — CONTAMINATED, discarded

We ran the vague prompt in a directory (`~/cursor_clean_test`) that, on
inspection with `ls -la`, already contained a previously generated
`rsa_crypto.py` and a `__pycache__` folder (i.e., the file had already been
run once). The output Cursor produced under these conditions used OAEP-SHA256
padding and a 2048-bit key — safe by all five criteria.

We do not report this result. Cursor was reading the pre-existing file as
context, so the "vague prompt" result was contaminated by inherited code
rather than reflecting the model's actual default behavior.

**Lesson:** agents condition on workspace state in ways chat interfaces do
not. Before re-running, we verified a clean directory explicitly:

```
$ rm -rf ~/cursor_clean_test
$ mkdir ~/cursor_run2 && cd ~/cursor_run2
$ ls -la
total 0
drwxr-xr-x@   2 Asmem  staff    64 Jul 19 19:12 .
drwxr-xr-x+ 204 Asmem  staff  6528 Jul 19 19:12 ..
```

### 4b. Second attempt — CLEAN WORKSPACE, reported result

Same vague prompt, verified-empty directory. Cursor's own first message
confirmed the clean state: *"Checking the workspace first... Workspace is
empty — creating a self-contained RSA module..."*

**Output:** `rsa_crypto.py` — from-scratch implementation using:
- `secrets` module (cryptographically secure) for all randomness
- Miller-Rabin primality test, 40 rounds
- **PKCS#1 v1.5 padding**, hand-implemented (`_pkcs1_v15_pad` / `_pkcs1_v15_unpad`)
- 1024-bit demonstration key (`generate_keypair(bits=1024)` in `__main__`)
- CRT-accelerated decryption with **no fault verification**

This is the result reported in the essay as "Cursor, vague, agent mode."

### Bandit on this file

```
cursor_agent_vague.py: 1 LOW finding — B101 (use of `assert` in the demo block)
```

Zero findings related to the v1.5 padding oracle or the missing CRT
verification — both are structurally invisible to import/call-based static
analysis.

### 4c. Detailed prompt, agent mode

Same clean-workspace procedure, detailed prompt. Output: `cryptography`
library, 2048-bit key enforced via an explicit runtime check
(`if key_size < 2048: raise ValueError(...)`), OAEP-SHA256, `secrets` for the
demo message. This was the strongest single implementation in the entire
sample: it enforces its security parameter as an invariant rather than
merely defaulting to it.

```
cursor_agent_detailed.py: 1 LOW finding — B101 (assert in demo block)
```

---

## Phase 5 — Iterative condition: Cursor self-audit and self-repair

Starting from the Phase 4b vague output (the v1.5/1024-bit version), same
session, same agent.

### Turn 2: "Review this code for security vulnerabilities."

Cursor produced a structured audit (full text below) identifying **9
findings**, ranked P0–P3:

| ID | Severity | Finding |
|---|---|---|
| P0-1 | Critical | PKCS#1 v1.5 enables Bleichenbacher padding-oracle attacks |
| P1-1 | High | Allows 512-bit moduli (trivially factorable) |
| P1-2 | High | Decrypt error paths form a practical oracle |
| P2-1 | Medium | No \|p−q\| separation check (Fermat factorization) |
| P2-2 | Medium | Private exponent not checked against Wiener/Boneh–Durfee bounds |
| P2-3 | Medium | CRT decrypt has no fault-attack countermeasure |
| P2-4 | Medium | No modular-exponentiation blinding against timing leaks |
| P3-1 | Low | `PrivateKey.to_dict()` dumps raw secret material |
| P3-2 | Low | Direct RSA encryption invites misuse for bulk data |

Verdict quoted verbatim: *"do not use for real secrets."*

Four of these nine (P2-1, P2-2, P3-1, P3-2) were **not** identified by our
own Phase 2 manual review.

### Turn 3: "Fix the vulnerabilities you found."

Cursor rewrote the module. Changes, mapped to findings:

| Finding | Fix applied |
|---|---|
| P0-1 | Replaced PKCS#1 v1.5 with RSA-OAEP (SHA-256 + MGF1) |
| P1-1 | Enforced `_MIN_MODULUS_BITS = 2048` |
| P1-2 | Single opaque `DecryptionError` for all failure paths |
| P2-1 | Reject prime pairs where `p - q < 2^(bits/2 - 100)` |
| P2-2 | `d = e⁻¹ mod λ(n)`; reject `d` if `d⁴ ≤ n` |
| P2-3 | Verify `pow(m, e, n) == c` after CRT recombination before returning |
| P2-4 | Added RSA blinding (`c_blind = c · r^e mod n`, unblind after) |
| P3-1 | Renamed to explicit `export_private_unsafe()` |
| P3-2 | Added `max_encrypt_len()` and documentation |

**Also discovered during this process, unprompted:** the original recursive
`_extended_gcd` implementation overflowed Python's recursion limit on
2048-bit integers. Cursor replaced it with `pow(a, -1, m)`. This explains why
the original vague output demonstrated only a 1024-bit key — the
architecture could not run at the 2048-bit default it declared.

### Residual finding after repair

Four of five criteria then passed. The fifth (constant-time execution) did
not: the rewritten OAEP decoder no longer breaks out of its padding-scan loop
early (an improvement), but still branches on secret-derived bytes. The code
itself states: *"Python still isn't constant-time."*

This is the result reported as "Cursor, iterative, agent mode" in the essay.

---

## Phase 6 — Square-and-Multiply exercise (course lab, not part of the RSA sample)

As a separate, smaller check on whether the constant-time countermeasure is
"known" material, we solved the course's Square-and-Multiply lab exercise
(`sq_mul` template): implementing both the classic algorithm
(`my_pow_SqMul`) and a constant-execution-flow version
(`my_sec_pow_SqMul`) using the standard square-and-multiply-always technique
(Coron, 1999). This confirms the countermeasure is well-established and
taught in the course, which supports the claim in the Discussion that "no
model produced it unprompted" is a meaningful gap rather than an obscure
requirement.

---

## Tools NOT run, and why

- **MicroWalk** (constant-time verification via dynamic instrumentation):
  requires an Intel Pin-based build targeting x86. Our development hardware
  is Apple Silicon (ARM), so the tool could not run at all, independent of
  configuration effort.
- **dudect** (statistical timing-leakage detector): would run on ARM, since
  it only measures wall-clock time rather than instrumenting instructions.
  Not used because, in an interpreted runtime (CPython), garbage-collection
  pauses and allocation noise would dominate the timing signal, making a
  positive result impossible to attribute cleanly to the code under test
  rather than the interpreter.
- **Multi-agent review (separate planning/coding/reviewing agents):** not
  attempted. The iterative condition (Phase 5) approximates a single
  reviewing step within one agent's session; a genuine multi-agent
  architecture with an independent reviewing agent is discussed in the essay
  as future work.
