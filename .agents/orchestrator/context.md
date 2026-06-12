# Project Context: EMPIRE AD Lab Vulnerability Documentation

## Background
The EMPIRE AD lab is a Windows Active Directory CTF environment build automation repository using Ansible. It injects a large number of vulnerabilities (over 382 unique checks defined in live verifier, and potentially 500+ configuration points). We need to extract all configurations from `ansible/roles/vuln_*` and document them.

## Key Files & Directories
- `ansible/roles/vuln_*`: Subdirectories containing vulnerability configurations (ADCS, Kerberos, Web Apps, etc.).
- `docs/`: Existing documentation files (`02-recon.md` to `07-forest-compromise.md`) mapping phases of attack.
- `scripts/verify_vulns.py`: Existing live-lab verifier script which has hardcoded lists of vulnerability IDs (382 of them).
- `PLAN.md`: Repository attack-vector matrix and topology design.

## Target Output
- Detailed documentation updates in `docs/` containing explanations, commands, and Mermaid diagrams.
- A static verification script in `scripts/check_docs.py` (or similar) that validates tag coverage (>95%) and Mermaid correctness.
