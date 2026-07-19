# Artifact: AI Generation of Cryptographic Schemes

This repository is the artifact referenced in the essay *"AI Generation of
Cryptographic Schemes"* (Moamen Abdelrahman, University of Lübeck, Secure
AI Code-Generation Seminar). It contains every prompt, every generated code
file, all tool output, and a full chronological log of every experimental
attempt — including the ones that did not go as planned.

The essay states conclusions in three pages. This repository is where the
evidence for those conclusions lives.

## Structure

```
artifact/
├── README.md                          — this file
├── prompts/
│   └── all_prompts.md                 — every prompt used, verbatim
├── generated_code/
│   ├── chatgpt/   (vague.py, detailed.py, vague.java, detailed.java)
│   ├── claude/    (vague.py, detailed.py, vague.java, detailed.java)
│   ├── copilot/   (vague.py, detailed.py)
│   └── cursor/    (vague_clean_workspace.py, detailed.py)
├── tool_output/
│   ├── bandit_spotbugs_raw_output.md  — full Bandit + SpotBugs console output
│   └── cursor_llm_audit_full_text.md  — full text of the LLM self-audit (9 findings)
└── setup_log/
    └── full_experimental_log.md       — every phase, in order, including
                                          the discarded contaminated trial
                                          and why it was discarded
```

## How this maps to the essay

| Essay claim | Where the evidence is |
|---|---|
| Table 1 (security evaluation) | `generated_code/*` + `tool_output/bandit_spotbugs_raw_output.md` |
| "Cursor gave nine ranked findings..." | `tool_output/cursor_llm_audit_full_text.md` |
| "Our first Cursor trial ran in a directory with an earlier file..." | `setup_log/full_experimental_log.md`, Phase 4a |
| "Bandit's only two HIGH findings went to Claude..." | `tool_output/bandit_spotbugs_raw_output.md` |
| The three verbatim prompts (vague/detailed/iterative) | `prompts/all_prompts.md` |
| "MicroWalk... unavailable rather than inconvenient" | `setup_log/full_experimental_log.md`, "Tools NOT run" section |

## Reproducing

Python files can be run directly with Python 3.10+ and the dependencies
they import (`cryptography`, `pycryptodome`, or none for the from-scratch
implementations). Java files must be renamed to match their public class
name before compiling (see `setup_log/full_experimental_log.md` for the
exact mapping used).

```bash
pip install cryptography pycryptodome
python3 generated_code/chatgpt/vague.py
```
