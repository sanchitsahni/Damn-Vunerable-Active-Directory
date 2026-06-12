# Project: EMPIRE AD Lab Vulnerability Documentation & Verification

## Architecture
This project involves scanning the Ansible role files in `ansible/roles/vuln_*` to extract vulnerability tags, updating documentation in `docs/` with details on execution and attack paths, and creating a validation tool `scripts/check_docs.py` to assert documentation coverage.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1: Exploration & Inventory | Extract all vulnerability tags from `ansible/roles/vuln_*` and check current docs coverage. | None | DONE |
| 2 | M2: Documentation Design | Define documentation structure, updates layout, and plan Mermaid diagrams for complex chains. | M1 | DONE |
| 3 | M3: Verification Tooling | Implement `scripts/check_docs.py` to parse roles/docs, verify >95% coverage and valid Mermaid. | M1, M2 | DONE |
| 4 | M4: Documentation Updates | Update/create Markdown documentation files with detailed explanations, terminal/PowerShell commands, and Mermaid diagrams. | M2, M3 | DONE |
| 5 | M5: Verification & Sign-off | Run static validation script, achieve 100% verification, and output final report. | M4 | DONE |

## Code Layout
- `ansible/roles/vuln_*` — Source files containing vulnerability configurations (specifically `.yml` files).
- `docs/` — Target documentation directory (e.g., `docs/03-credential-access.md`, `docs/05-privilege-escalation.md`, etc.).
- `scripts/check_docs.py` — Target location for the new static verification script.
