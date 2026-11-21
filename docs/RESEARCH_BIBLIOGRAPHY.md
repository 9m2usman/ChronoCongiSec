# Research Bibliography — Verified Initial Sources

Status: initial source verification, not a completed systematic review. Claims below are limited to the sources and metadata checked on 2026-11-15.

## R-001 — AgentPoison

- **Title:** AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases
- **Authors:** Zhaorun Chen, Zhen Xiang, Chaowei Xiao, Dawn Song, Bo Li
- **Venue/year:** NeurIPS 2024, Main Conference Track
- **Identifier:** DOI 10.52202/079017-4136; arXiv:2407.12784
- **Primary source:** https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html
- **Method:** Backdoor-style poisoning of long-term memory or RAG knowledge bases. Trigger generation is formulated as constrained optimization to increase retrieval of poisoned demonstrations for trigger-bearing queries while retaining benign behavior for other queries.
- **Evaluation:** Three agent settings (autonomous driving, knowledge-intensive QA, healthcare). The paper reports average attack success of at least 80% with poison rate below 0.1% and benign-performance impact no greater than 1% in its evaluated settings.
- **Product translation:** Add memory-write provenance and authorization, adversarial memory ingestion tests, retrieval influence measurements, and poisoned-memory lifecycle evaluation.
- **Limitations:** Attack paper, not a defensive detector. Results are setting-specific.

## R-002 — MPBench memory-poisoning study

- **Title:** From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents
- **Authors:** Pritam Dash, Tongyu Ge, Aditi Jain, Tanmay Shah, Zhiwei Shang
- **Status/date:** arXiv preprint, submitted 2026-06-03; version 2 dated 2026-06-18.
- **Identifier:** arXiv:2606.04329
- **Primary source:** https://arxiv.org/abs/2606.04329
- **Method:** Studies four memory write channels (explicit instruction-executed write, system-prompt-driven write, compaction-driven write, experience-to-procedure), identifies nine structural vulnerabilities and proposes a six-class taxonomy and MPBench.
- **Evaluation:** The paper reports average attack success rate 50.46% and retrieval success rate 41.05% across its two evaluated agents.
- **Product translation:** Model write channels explicitly in ingestion; tag source integrity and transformation lineage; evaluate poisoning by channel and downstream retrieval/action influence.
- **Limitations:** arXiv preprint; bounded by evaluated agents and benchmark.

## R-003 — AgentRewind

- **Title:** AgentRewind: Recoverable Execution for Long-Horizon LLM Agents
- **Authors:** Yu Zhuang, Kefei Chen, Yitong Duan, Shuxin Zheng, Jian Li, Xu-Yao Zhang
- **Status/date:** arXiv preprint, 2026-08-14.
- **Identifier:** arXiv:2608.14380
- **Primary source:** https://arxiv.org/abs/2608.14380
- **Code:** https://github.com/Futuresis/replay-agent-recorder
- **Dataset:** https://github.com/Kelvin-Coffee/MettleBench
- **Method:** Aligned checkpoints of agent context and controlled environment; rewind to a selected earlier checkpoint and resume, retaining a summary of the previous attempt as rewind memory.
- **Evaluation:** Introduces MettleBench for long-horizon engineering assignments. Exact numerical tables must be extracted from the full paper before quantitative comparison.
- **Product translation:** Separate agent-context checkpoint, controlled-environment checkpoint, and external side-effect ledger; add preview/restore/resume state machine and recovery validation.
- **Limitations:** Rewinding a controlled environment does not reverse arbitrary external side effects.

## R-004 — ChronoMem (temporal multimodal memory)

- **Title:** Temporal Multimodal Memory Banks for Agentic Reasoning
- **Author:** Prasanth Yadla
- **Venue/year:** ICCV 2025 Workshop proceedings (MMRAgI), pp. 6519–6526.
- **Primary source:** https://openaccess.thecvf.com/content/ICCV2025W/MMRAgI/html/Yadla_Temporal_Multimodal_Memory_Banks_for_Agentic_Reasoning_ICCVW_2025_paper.html
- **Method:** Persistent multimodal episodic memory using hierarchical memory encoding, cross-modal temporal indexing/binding, consolidation, and experience-guided retrieval.
- **Evaluation:** Adapted tasks for navigation (AVLMaps), human interaction (MTPChat), and scientific assistance (RVTALL); reports average improvements of 3.3% on long-term task performance versus extended-context methods and 3.7% in retrieval accuracy versus systems without persistent memory.
- **Product translation:** Relevant to temporal/episodic retrieval if multimodal experience is in scope. It is not a cryptographic checkpoint store or rollback engine.
- **Limitations:** Workshop paper; not a security or memory-integrity method. KnowledgeLine's class named ChronoMem must not be represented as a faithful implementation without method comparison.

## R-005 — Runtime Policy Enforcement for MCP-Based LLM Agents

- **Title:** Runtime Policy Enforcement for MCP-Based LLM Agents
- **Authors:** Shanshan Wang, Sizheng Zhu, Rende Li
- **Venue/year:** Electronics, 2026, 15(13), 2829; published 2026-06-27.
- **Identifier:** DOI 10.3390/electronics15132829
- **Primary source:** https://www.mdpi.com/2079-9292/15/13/2829
- **Method:** Tool-boundary Policy Enforcement Point with declarative rules, cross-step source-integrity/data-sensitivity labels, and synchronous SHA-256 hash-chained audit events.
- **Evaluation:** Controlled attack/benign evaluations, ablation, cross-model observations and preliminary MCP stdio integration. The authors characterize these as bounded mechanism-coverage evidence, not production deployability proof.
- **Product translation:** Implement deterministic tool-boundary mediation, provenance/sensitivity label propagation, deny-decision logging, and ablation tests.
- **Limitations:** Coarse label tracking has blind spots; not universal defense against tool-chain attacks.

## R-006 — AgentDojo

- **Title:** AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents
- **Authors:** Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr
- **Status/date:** arXiv preprint, 2024-06-19; pin the official benchmark release before evaluation.
- **Identifier:** arXiv:2406.13352
- **Primary source:** https://arxiv.org/abs/2406.13352
- **Code:** https://github.com/ethz-spylab/agentdojo
- **Method:** Dynamic environment for evaluating tool-using agents exposed to untrusted tool-returned content. The paper reports 97 realistic tasks and 629 security test cases.
- **Product translation:** External prompt-injection/tool-use evaluation baseline; add separate persistent-memory poisoning tests.
- **Limitations:** Results depend on task suite, model, harness and defense configuration.

## R-007 — MCP ecosystem security survey

- **Title:** Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions
- **Authors:** Xinyi Hou, Yanjie Zhao, Shenao Wang, Haoyu Wang
- **Venue/year:** ACM Transactions on Software Engineering and Methodology, 2026, Volume 35, Issue 10, Article 302.
- **Identifier:** DOI 10.1145/3796519
- **Primary source:** https://doi.org/10.1145/3796519
- **Method:** Maps MCP server lifecycle and analyzes security/privacy threats with case studies and safeguards.
- **Product translation:** Use as lifecycle threat-model input for server registration, deployment, operation and maintenance.
- **Limitations:** A survey/case-study taxonomy is not a tested gateway implementation.

## Unverified concepts

- **Dual Trace:** No unique original paper matching the project's specific cognitive-trace/execution-trace pairing was established in this initial search. Treat it as an original product architecture pattern until a precise primary source is identified.
- **ChronoMem:** The verified 2025 paper concerns multimodal episodic memory. Do not conflate it with KnowledgeLine's joint-state checkpoint implementation.
- **AgentRewind:** Verified as AgentRewind (arXiv:2608.14380); KnowledgeLine's recovery engine is not yet shown to be a faithful implementation.
