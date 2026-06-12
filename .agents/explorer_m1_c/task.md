# Task: Exploration & Inventory of Vulnerabilities - Group C

## Objective
Analyze specific `.yml` files in `ansible/roles` to extract every injected vulnerability ID/tag and check how many of these are currently documented in the repository's documentation files under `docs/`.

## Target Roles
- `vuln_persistence`
- `vuln_privesc`
- `vuln_recon`
- `vuln_traffic_sim`
- `vuln_victim_exec`
- `vuln_web_apps`

## Working Directory
/home/sanchit/DVWA/.agents/explorer_m1_c

## Instructions
1. Find all `.yml` task files in the target roles.
2. Extract all vulnerability tags (look for comments, task names, GPO names, etc. matching patterns like `IA-xxx`, `REC-xxx`, `ENUM-xxx`, `CRED-xxx`, `LAT-xxx`, `PE-xxx`, `PER-xxx`, `DF-xxx`, or `ESC` tags).
3. Search files under `docs/` to see which tags are already documented (with description and execution commands).
4. Save the inventory of tags and their documentation status in `handoff.md`.
