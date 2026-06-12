# Task: Exploration & Inventory of Vulnerabilities

## Objective
Analyze all `.yml` files in the `ansible/roles/vuln_*` directories to extract every injected vulnerability ID/tag (e.g. CRED-001, ESC1, PE-005, etc.) and check how many of these are currently documented in the repository's documentation files under `docs/`.

## Working Directory
/home/sanchit/DVWA/.agents/explorer_m1

## Instructions
1. Find all `.yml` task files in `ansible/roles/vuln_*`.
2. Extract all vulnerability tags (look for comments, task names, GPO names, etc. matching patterns like `IA-xxx`, `REC-xxx`, `ENUM-xxx`, `CRED-xxx`, `LAT-xxx`, `PE-xxx`, `PER-xxx`, `DF-xxx`, or `ESC` tags).
3. Search files under `docs/` to see which tags are already documented (with description and execution commands).
4. Save the inventory of tags and their documentation status in `handoff.md`.
