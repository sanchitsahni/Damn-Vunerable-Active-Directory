## 2026-06-12T09:10:10Z
Your working directory is /home/sanchit/DVWA/.agents/worker_m3.
Your identity is: Verification Tooling Worker.
Your parent is orchestrator (conversation ID: f98a9181-176c-4ec1-ba51-81ac288c59c2).

Your task:
1. Implement a Python verification script at `/home/sanchit/DVWA/scripts/check_docs.py` to statically parse the Ansible roles in `ansible/roles/vuln_*` for vulnerability tags/IDs and confirm that >95% of them are present and explained in the documentation files under `docs/`.
2. The script must:
   - Scan all `.yml` task files in `ansible/roles/vuln_*` (recursively) and extract all unique vulnerability tags/IDs. It must match patterns like `(?:IA|REC|ENUM|CRED|LAT|PE|PER|DF|NET|CLO|SRV|WEB)-(?:CVE-\d{4}-\d+|\d+)` or `B\d`, `Redis`, `Memcached`, `MongoDB`, `MySQL`, `WebApp` (case-insensitive).
   - Scan all `.md` files under `docs/` (recursively) for the presence of these tags.
   - For each tag, check if it is documented:
     - It must appear in a section header or a line starting with `### <TAG>` or similar, or have a specific detail block.
     - (Optional but recommended) check if there is an explanation and commands.
   - Output the list of found tags, documented tags, undocumented tags, and calculate the coverage percentage.
   - Return exit code 0 if coverage is >95%, otherwise exit code 1.
   - Validate that all Mermaid diagrams in the `.md` files have correct open/close syntax (e.g. starting with ````mermaid` and ending with ````).
3. Verify that the script executes correctly without syntax errors. Run the script using Python 3 and verify its stdout.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A Forensic Auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Document your findings and verification command results in `/home/sanchit/DVWA/.agents/worker_m3/handoff.md` and report back when done.
