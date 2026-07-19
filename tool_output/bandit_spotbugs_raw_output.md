# Bandit Output — All Python Files

## Phase 1: ChatGPT + Claude (chat, both prompt conditions)

Command: `bandit chatgpt_vague.py chatgpt_detailed.py claude_vague.py claude_detailed.py`

```
[main] INFO profile include tests: None
[main] INFO profile exclude tests: None
[main] INFO cli include tests: None
[main] INFO cli exclude tests: None
[main] INFO running on Python 3.13.9
Run started:2026-06-15 01:30:51.669534+00:00

Test results:
>> Issue: [B413:blacklist] The pyCrypto library and its module RSA are no
   longer actively maintained and have been deprecated. Consider using
   pyca/cryptography library.
   Severity: High   Confidence: High
   CWE: CWE-327
   Location: ./claude_detailed.py:5:0

>> Issue: [B413:blacklist] The pyCrypto library and its module PKCS1_OAEP
   are no longer actively maintained and have been deprecated. Consider
   using pyca/cryptography library.
   Severity: High   Confidence: High
   CWE: CWE-327
   Location: ./claude_detailed.py:6:0

>> Issue: [B413:blacklist] The pyCrypto library and its module RSA are no
   longer actively maintained and have been deprecated. Consider using
   pyca/cryptography library.
   Severity: High   Confidence: High
   CWE: CWE-327
   Location: ./claude_vague.py:3:0

>> Issue: [B413:blacklist] The pyCrypto library and its module PKCS1_OAEP
   are no longer actively maintained and have been deprecated. Consider
   using pyca/cryptography library.
   Severity: High   Confidence: High
   CWE: CWE-327
   Location: ./claude_vague.py:4:0

Code scanned:
    Total lines of code: 112
    Total lines skipped (#nosec): 0

Run metrics:
    Total issues (by severity):
        Undefined: 0
        Low: 0
        Medium: 0
        High: 4
    Total issues (by confidence):
        Undefined: 0
        Low: 0
        Medium: 0
        High: 4
Files skipped (0):
```

**Note:** zero findings on `chatgpt_vague.py` (12-bit textbook RSA,
no imports Bandit's ruleset recognizes) and zero on `chatgpt_detailed.py`.

---

## Phase 3: GitHub Copilot (chat)

```
copilot_chat_vague.py:
  3 issues, all LOW severity, rule B311
  (use of `random` / `random.getrandbits` — not a CSPRNG)

copilot_chat_detailed.py:
  0 issues
```

---

## Phase 4: Cursor (agent, clean workspace)

```
cursor_agent_vague.py:
  1 issue, LOW severity, rule B101
  (use of `assert` in demo/__main__ block — not related to the
  PKCS#1 v1.5 padding oracle or missing CRT verification in the same file)

cursor_agent_detailed.py:
  1 issue, LOW severity, rule B101
  (same — assert in demo block)
```

---

# SpotBugs Output — All Java Files

Java files renamed to match public class names before compiling:
`chatgpt_vague.java` → `SimpleRSA.java`
`chatgpt_detailed.java` → `RSAExample.java`
`claude_vague.java` → `RSAEncryption.java`
`claude_detailed.java` → `RSA.java`

Compiled with `javac`, scanned with:
`~/spotbugs-4.10.2/bin/spotbugs -textui <ClassName>.class`

```
M D DLS: Dead store to $L4 in SimpleRSA.main(String[])
At SimpleRSA.java:[line 10]

M B CT: Exception thrown in class RSAExample at new RSAExample() will leave
the constructor. The object under construction remains partially
initialized and may be vulnerable to Finalizer attacks.
At RSAExample.java:[line 15]

(RSAEncryption.class: no output — 0 findings)
(RSA.class: no output — 0 findings)
```

**Summary:**

| File | Findings |
|---|---|
| SimpleRSA.class (ChatGPT vague — 8-bit textbook RSA) | 1 (dead store) |
| RSAExample.class (ChatGPT detailed — OAEP/2048) | 1 (finalizer risk) |
| RSAEncryption.class (Claude vague — OAEP/2048) | 0 |
| RSA.class (Claude detailed — OAEP/2048 + explicit param spec) | 0 |

Neither SpotBugs finding relates to key size, padding, or randomness — the
tool caught a minor code-quality issue in the safe implementation and a
theoretical exception-safety issue in another safe implementation, while
saying nothing about the 8-bit modulus in `SimpleRSA.class`.
