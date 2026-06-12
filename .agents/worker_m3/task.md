# Task: Verification Tooling

## Objective
Implement a Python verification script at `/home/sanchit/DVWA/scripts/check_docs.py` to statically parse the Ansible roles in `ansible/roles/vuln_*` for vulnerability tags/IDs and confirm that >95% of them are present and explained in the documentation files under `docs/`.

## Working Directory
/home/sanchit/DVWA/.agents/worker_m3

## Instructions
1. Write `/home/sanchit/DVWA/scripts/check_docs.py`. The script must:
   - Scan all `.yml` task files in `ansible/roles/vuln_*` and extract all vulnerability tags matching patterns like `(?:IA|REC|ENUM|CRED|LAT|PE|PER|DF|NET|CLO|SRV|WEB)-(?:CVE-\d{4}-\d+|\d+)` or `B\d`, `Redis`, `Memcached`, `MongoDB`, `MySQL`, `WebApp` (case-insensitive).
   - Scan all `.md` files under `docs/` (recursively) for the presence of these tags.
   - For each tag, check if it is documented:
     - It must appear in a section header or a line starting with `### <TAG>` or similar, or have a specific detail block.
     - (Optional but recommended) check if there is an explanation and commands.
   - Output the list of found tags, documented tags, undocumented tags, and calculate the coverage percentage.
   - Return exit code 0 if coverage is >95%, otherwise exit code 1.
   - Validate that all Mermaid diagrams in the `.md` files have correct open/close syntax (e.g. starting with ````mermaid` and ending with ````).
2. Run syntax/check verification to ensure the script compiles and runs correctly.
3. Report back with the script execution output when done.
