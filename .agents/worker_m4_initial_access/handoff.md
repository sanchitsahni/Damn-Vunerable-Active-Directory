# Handoff Report — Initial Access Documentation

## 1. Observation
- The file `/home/sanchit/DVWA/docs/02a-initial-access.md` previously mapped `IA-007` to `AS-REP roast without credentials` (line 198):
  ```markdown
  ### IA-007 — AS-REP roast without credentials
  ```
- The Ansible role for vulnerability reconnaissance (`/home/sanchit/DVWA/ansible/roles/vuln_recon/tasks/main.yml`, lines 125-150) defines `IA-007` as Guest account enabled on `scarif`:
  ```yaml
  # IA-007: Guest account enabled on scarif
  ```
- Missing extended initial access vulnerability tags were identified in Jinja templates under `/home/sanchit/DVWA/ansible/roles/vuln_ia_surface/templates/`:
  - `ext_phishing.ps1.j2` defines:
    - `IA-052` (LNK file bait)
    - `IA-053` (AutoPlay enabled)
    - `IA-056` (HTA stub)
    - `IA-063` (CHM note)
  - `ext_services.ps1.j2` defines:
    - `IA-076` (IIS dir-browse)
    - `IA-078` (WebDAV authoring)
    - `IA-084` (RDP NLA off)
    - `IA-085` (OpenSSH password auth)
  - `ext_misconfig.ps1.j2` defines:
    - `IA-113` (weak default password policy)
    - `IA-114` (Weak-PSO fine-grained policy)
    - `IA-115` (AdminCount=1)
    - `IA-117` (MachineAccountQuota=100)
    - `IA-119` (plaintext credential planted in GPO)
  - `victim-exec.ps1` (under `/home/sanchit/DVWA/ansible/roles/vuln_victim_exec/files/`) references `IA-054` as an Office macro doc vector:
    ```powershell
    # AutoOpen / Document_Open VBA payload runs (IA-019..022 / IA-054).
    ```

## 2. Logic Chain
1. By examining the Ansible and PowerShell configuration templates, the exact vulnerabilities associated with each `IA-` tag were established.
2. `IA-007` in `02a-initial-access.md` was identified as mismatched with the codebase implementation where it acts as a guest account enablement on `scarif`.
3. To resolve this naming/mapping mismatch, `IA-007` in `/home/sanchit/DVWA/docs/02a-initial-access.md` was rewritten to document the `Guest account enabled on scarif` vulnerability, including execution steps and detection/prevention guidelines.
4. Because the general `AS-REP roasting` technique is already documented elsewhere (e.g. `CRED-002` in `docs/03-credential-access.md` and `ENUM-027` in `docs/02b-enumeration.md`), the `AS-REP roasting` reference in the `02a-initial-access.md` and `08-solve-path.md` decision trees was updated to reference `CRED-002`.
5. Under a new section header `## IA-052..119 — Extended Phishing, Services, and Domain Misconfigurations` in `/home/sanchit/DVWA/docs/02a-initial-access.md`, all the requested missing extended initial access tags (`IA-052`, `IA-053`, `IA-054`, `IA-056`, `IA-063`, `IA-076`, `IA-078`, `IA-084`, `IA-085`, `IA-113`, `IA-114`, `IA-115`, `IA-117`, `IA-119`) were documented using the identical layout of existing write-ups (Heading, What it is, Why it works in EMPIRE, Tools, Steps, Detection, and Prevention).
6. The decision tree in `02a-initial-access.md` was updated to incorporate these new `IA-` tags under the appropriate branches (`exposed services`, `reach users`, `Domain Misconfigurations`).

## 3. Caveats
- Checked configuration mappings statically against templates and playbooks in the repository. No live VM deployment or dynamic scanning was performed.

## 4. Conclusion
All missing `IA-` tags have been documented in `/home/sanchit/DVWA/docs/02a-initial-access.md` with layout formatting identical to the existing codebase documentation. The mismatch on `IA-007` has been resolved by documenting the Guest account vulnerability, and the decision trees have been successfully updated.

## 5. Verification Method
- Open `/home/sanchit/DVWA/docs/02a-initial-access.md` and search for the updated `### IA-007` heading and verify the presence of headings for all new tags (up to `IA-119`).
- Verify that the layout matches precisely (Heading, What it is, Why it works, Tools, Steps, Detection, Prevention).
- Check the decision trees in both `/home/sanchit/DVWA/docs/02a-initial-access.md` and `/home/sanchit/DVWA/docs/08-solve-path.md` to ensure `IA-007` is mapped correctly and all new tags are listed.
