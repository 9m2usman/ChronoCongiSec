# Research-to-Implementation Matrix — Initial

| ID | Research | Proposed capability | Status | Required validation |
|---|---|---|---|---|
| R-001 | AgentPoison | Threat-model and test poisoned memory retrieval/trigger persistence | Planned | Reproduce in isolated authorized test; measure ASR and benign utility |
| R-002 | MPBench | Write-channel taxonomy and memory-poisoning evaluation | Planned | Map four write channels; report per-channel detection, retrieval influence, false positives |
| R-003 | AgentRewind | Aligned context/environment checkpoints and resumable rewind | Planned | Checkpoint equivalence, state restoration, task progress, side-effect accounting |
| R-004 | ChronoMem (Yadla 2025) | Optional temporal multimodal episodic retrieval | Research candidate | Compare hierarchical temporal retrieval with chronological/vector baselines |
| R-005 | Runtime Policy Enforcement for MCP Agents | Deterministic PEP, cross-step labels, tamper-evident audit | Generic gateway foundation implemented; paper-specific method not implemented | Rule coverage, label propagation ablation, ASR/TSR/FPR/FNR, audit tamper tests |
| R-006 | AgentDojo | Tool-use and indirect prompt-injection evaluation | Planned | Pin benchmark version; report task utility and security outcomes separately |
| R-007 | MCP lifecycle security survey | MCP lifecycle threat model and integration checklist | Planned | Threat-to-control coverage and negative tests |
| O-001 | Dual cognitive/execution trace | Correlated structured trace events | Original product architecture proposal | Trace completeness, correlation accuracy, missing-event and ordering tests |

## Fidelity labels

- **Faithful:** algorithm and assumptions match the source method.
- **Adapted:** selected method is changed for product constraints; changes are explicit.
- **Infrastructure:** supports a method but is not itself the research contribution.
- **Original:** project-created design or algorithm.
- **Hypothesis:** unvalidated idea awaiting experiment.

The initial gateway code is generic engineering infrastructure. It is not a faithful implementation of R-005 until the paper's exact rule semantics, source-integrity/data-sensitivity label model, propagation behavior, and evaluation protocol are implemented and tested.
