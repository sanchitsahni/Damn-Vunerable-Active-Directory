## 2026-06-12T09:16:38Z

Your working directory is /home/sanchit/DVWA/.agents/worker_m4_linux.
Your identity is: Linux Member Documentation Worker.
Your parent is orchestrator (conversation ID: f98a9181-176c-4ec1-ba51-81ac288c59c2).

Your task:
1. Create `/home/sanchit/DVWA/docs/hosts/linux01-corp.md` to document all local Linux LPEs and services vulnerabilities on the Mandalore Base member server.
2. The vulnerabilities/tags to document are: B1 to B8 (krb5.keytab, passwordless sudo, SSSD cache, cron job, SUID find, NFS export no_root_squash, weak SSH) and services (Redis, MongoDB, Memcached, MySQL, WebApp Python RCE).
3. For each tag/vulnerability, provide:
   - Heading
   - Explanation of the vulnerability
   - Concrete execution/exploit commands (bash/linux command blocks)
   - Detection and prevention.
4. Ensure layout formatting is identical to other files in `docs/hosts/`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A Forensic Auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Write your handoff report to `handoff.md` in your directory when complete.
