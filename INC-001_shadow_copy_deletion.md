# Incident Report INC-001 - Backup and Recovery Deletion on a Workstation

| Field | Value |
|---|---|
| Report ID | INC-001 |
| Company | NileCare (fictional) |
| Detection | Sigma rule `nilecare_shadow_copy_deletion.yml` |
| Severity | High (would be Critical if the host were an EMR or file server) |
| Related risks | R-01 (ransomware), R-04 (unrecoverable backups) |
| Related controls | ISO 27001:2022 A.8.13, A.8.7, A.8.16, A.5.26 |
| Status | Closed (lab exercise) |

> **Important:** this is a training exercise. The log is a public sample (`PanacheSysmon_vs_AtomicRedTeam01.evtx` from the EVTX-ATTACK-SAMPLES project), which records simulated attacker tests (Atomic Red Team). It is used here as a stand-in for a NileCare workstation. No real NileCare incident happened.

## 1. Summary
Three commands that remove recovery options ran on one Windows host within about 12 seconds, all started through `cmd.exe` by the same user with high integrity. This pattern is typical just before ransomware encrypts files. The Sigma rule detected all three commands.

## 2. Timeline (UTC, from the log)
| Time | Event | Command |
|---|---|---|
| 2019-07-19 14:47:40 | Delete shadow copies | `vssadmin.exe delete shadows /all /quiet` |
| 2019-07-19 14:47:45 | Delete backup catalog | `wbadmin.exe delete catalog -quiet` |
| 2019-07-19 14:47:52 | Disable recovery mode | `bcdedit.exe /set {default} recoveryenabled no` |

## 3. Evidence
| Field | Value |
|---|---|
| Host | MSEDGEWIN10 |
| User | MSEDGEWIN10\IEUser |
| Integrity level | High |
| Parent process | `cmd.exe /c "<command>"` (one cmd per command) |
| Log source | Sysmon Event ID 1 (process creation) |
| vssadmin SHA256 | D7577FB88CCA3169C7931DC0D8EC9A444227DC14F6C71D6D39D86A0C5CAD1976 |
| wbadmin SHA256 | 3F31A25ABBF5E75F49C2B596034BA12F95D92FE5AC06D62F15995AF8499908EF |
| bcdedit SHA256 | 1ADEA035FBFF2FC188FF4CD27076BED9E03DB5ECEFFBD59F875A2A1FEEFB16F0 |

The three binaries are normal Windows tools. The threat is how they were used (quiet deletion of recovery data), not the files themselves.

## 4. Analysis
- **Technique:** T1490 Inhibit System Recovery (ATT&CK, Impact).
- **Why it matters for NileCare:** if backups and shadow copies are removed, restoring EMR or file server data depends only on the backup system. The gap assessment showed NileCare has no offline or immutable backup copy and no tested restores (A.8.13).
- **Confidence:** high that this is malicious or a test. Legitimate administrators rarely run all three together with `/quiet`.
- **Not seen in the log:** file encryption, ransom note, or network spread. The log does not show what happened next.

## 5. Response (following the Incident Response Policy)
1. **Triage:** severity High; escalate to Critical if the host is an EMR, database or file server.
2. **Contain:** isolate the host from the network; disable the user account; keep the machine powered on until memory and logs are preserved.
3. **Investigate:** check the same host for file renames or encryption, new admin accounts, and unusual outbound connections; search other hosts for the same commands.
4. **Recover:** confirm backups are intact and offline copies are unaffected; rebuild the host from a clean image.
5. **Notify:** IT Manager immediately; management if the host holds patient data; Legal and Compliance decides on PDPL notification if personal data was exposed.

## 6. Lessons learned
- The rule fired on all three commands. The `wmic shadowcopy delete` variant was not in this log, so it is untested.
- Add a correlation (two or more of these commands on one host within 5 minutes) to raise the alert to Critical.
- Close the backup gap: offline or immutable copy and quarterly restore tests (policy NC-POL-003).
- Alerts on this behavior only help if someone responds quickly: define who gets the alert and the response time.
