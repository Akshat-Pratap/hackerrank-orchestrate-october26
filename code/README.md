# Ghost Data Still Exists — Deletion-Audit Solution

Official Challenge Link: [https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)

## 1. Overview & Setup

This repository contains an autonomous, deterministic deletion-audit engine designed for the HackerRank Orchestrate challenge: **Ghost Data Still Exists**. It evaluates 518 customer deletion requests across distributed microservices, databases, replicas, backups, data flows, and search indexes to determine true privacy compliance at the cutoff timestamp (`audit_at`).

### Requirements & Setup
- Python 3.10+ (standard library only; no external heavy dependencies required).
- Tested on Windows, macOS, and Linux.

### Execution
To run the full end-to-end pipeline and generate `output.csv`:

```bash
python3 code/main.py
```

To validate the generated output:

```bash
python3 code/validate.py output.csv
```

To run the sample benchmark and cluster coverage audit:

```bash
python3 code/evaluation/main.py
```

---

## 2. Architecture & Design

The solution operates as a strictly grounded, deterministic pipeline with zero non-deterministic LLM hallucination risk during prediction generation:

1. **Request Authorization Classifier (`identity.py`)**:
   - Analyzes multilingual request text to detect whether the user actually authorized permanent account/data deletion.
   - Accurately classifies non-deletion requests (access inquiries, marketing opt-outs, rectification, exports, data portability) as `NOT_APPLICABLE` with `steps_json=[]`.

2. **Historical Identity Resolution (`identity.py`)**:
   - Reconstructs the complete identity graph (`user_id`, current and historical emails, phone numbers, SHA-256 email hashes) by joining `user_identities.csv` and historical change records in `user_audit_log.csv`.
   - Links accounts and resources across system boundaries regardless of whether older logs cite outdated email aliases.

3. **Multi-Format Grounded Evidence Loaders (`loaders.py`)**:
   - **SQL Databases & Replicas**: Parses SQLite-compatible dumps and SQL exports (`customer_data_primary`, `customer_data_read_replica`, `regional_replicas`, inventory tables). Detects replication drift where records remain on replicas while absent from primary.
   - **JSON Bundles & Service Exports**: Parses multi-snapshot bundles (`bundle_*.json`) matching inner snapshot capture timestamps, and service resource exports.
   - **Logs & Observability Streams**: Universally processes cloud runtime exports, pipe-delimited operational streams, RFC5424 syslog archives, and bracketed microservice logs using structured unescaping, KV extraction, and trace-correlation graphs.
   - **Text Handovers & Vision Cache**: Reads structured handover reports and cached OCR/multimodal extractions for PDF documents and UI screenshots.

4. **Temporal State Reconstruction (`timeline.py`)**:
   - Strictly enforces the `audit_at` cutoff invariant: evidence or activity captured after a case's `audit_at` is ignored.
   - Merges evidence observations with global `system_activity.csv` operations to reconstruct the true state at cutoff time.

5. **Policy Engine & Step Planner (`rules.py`, `plan.py`)**:
   - Implements `deletion_rules.csv` mapping every resource category (`USER_PROFILE`, `SEARCH_INDEX_ENTRY`, `SUPPORT_MESSAGE`, `SUPPORT_ATTACHMENT`, `ANALYTICS_PROFILE`, `DATA_FLOW`, `BACKUP_ARCHIVE`, `SECURITY_AUDIT_LOG`, `ACCOUNT_TOMBSTONE`).
   - For `ACCOUNT_TOMBSTONE`, validates that direct PII identifiers (name, email, phone) are purged while preserving stable user references.
   - Enforces strict remediation dependency ordering: disabling active data flows (`DISABLE_DATA_FLOW`) and blocking unsafe restore catalogs (`BLOCK_RESTORE`) before remediating downstream records (`DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`).
   - For `COMPLETE` requests, produces evidence-backed verification proofs (`VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_PRESENT`, `VERIFY_RECORD_ANONYMIZED`).

---

## 3. Account Assignment & Linking Rule

In distributed microservices where account services report profile deletions as anonymized resource identifiers without direct email links:
- Candidate accounts are identified by matching `DELETE_RECORD` events on `account_service` within `[reported_at - 80m, reported_at - 40m]`.
- Accounts already claimed by another subject via direct email/user_id links are pruned.
- Remaining candidates within each audit cluster are deterministically resolved via stable 1-to-1 matching (sorted by `reported_at`, then `case_id`).

---

## 4. Submission Artifacts

- `output.csv`: Complete prediction file containing 518 rows sorted by `case_id`.
- `code/`: Complete, self-contained codebase.
- `evaluation/evaluation_report.md`: Detailed accuracy metrics, sequence evaluations, failures and improvements, and custom test cases.
- `evaluation/usage_report.md`: Resource and token usage accounting ($0 cost, 0 LLM tokens, 100% deterministic).
- `log.txt`: Complete session log following `AGENTS.md` per-turn audit requirements.
