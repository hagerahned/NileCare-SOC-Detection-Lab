# NileCare SOC Detection Lab - Sigma Rules

Detection rules for the fictional company **NileCare**. Risk IDs (R-xx) and Annex A controls refer to the companion repository [NileCare-ISO27001-GRC-Project](https://github.com/hagerahned/NileCare-ISO27001-GRC-Project.git) (risk register, gap assessment, policies, network design). Each rule is written in [Sigma](https://github.com/SigmaHQ/sigma) format and linked to a risk in the risk register, an ATT&CK technique and ISO 27001:2022 Annex A controls. They help close gaps **A.8.15 Logging** and **A.8.16 Monitoring activities** from the gap assessment.

**Status:** syntax-validated with pySigma and tested with Chainsaw 2.17.1 on the public EVTX-ATTACK-SAMPLES logs (278 files). Results are below, including what could not be tested.

## Rules
| # | Rule file | Risk | ATT&CK | Annex A |
|---|---|---|---|---|
| 1 | `nilecare_failed_logon_bruteforce.yml` (rule + correlation) | R-03 | T1110 | A.8.5, A.8.15, A.8.16 |
| 2 | `nilecare_admin_group_membership_change.yml` | R-09 | T1098 | A.8.2, A.5.18, A.8.16 |
| 3 | `nilecare_patient_share_access.yml` | R-02 | T1039 | A.5.15, A.8.3, A.8.15 |
| 4 | `nilecare_powershell_encoded_command.yml` | R-03 | T1059.001, T1027 | A.8.7, A.8.16 |
| 5 | `nilecare_shadow_copy_deletion.yml` | R-01, R-04 | T1490 | A.8.13, A.8.7, A.8.16 |
| 6 | `nilecare_event_log_cleared.yml` | R-09, R-02 | T1070.001 | A.8.15, A.8.16 |
| 7 | `nilecare_disabled_account_logon_attempt.yml` | R-16 | T1078 | A.6.5, A.5.18, A.8.16 |

## Test results
| # | Result | Details |
|---|---|---|
| 1 | **Not testable** | The samples contain only 1 failed-logon event (4625), from a local source that the rule excludes on purpose. No brute-force sample exists. Chainsaw did not apply the correlation part. |
| 2 | **Detected** | 2 hits in `Persistence/Network_Service_Guest_added_to_admins_4732.evtx` (user added to Administrators). |
| 3 | **Logic verified, real rule not triggered** | 0 hits for `PatientRecords` (expected: the samples only contain `C$`, `IPC$`, `ADMIN$` shares). A temporary copy pointing to `ADMIN$` produced 19 hits in 3 lateral-movement samples, which proves the logic works on real 5145 events. |
| 4 | **Detected** | 1 hit in `Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` (`powershell.exe -nop -noni -enc ...`). |
| 5 | **Detected** | 3 hits in `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` (vssadmin, wbadmin, bcdedit). The `wmic` variant has no sample. See `incident-reports/INC-001`. |
| 6 | **Detected, needs a mapping change** | 24 hits, including the intended `DE_1102_security_log_cleared.evtx`. With Chainsaw's default mapping the rule finds nothing (see below). 23 other sample files also contain log-clear events, probably because the sample authors cleared logs before testing. |
| 7 | **Not testable** | Syntax validated only. The only failed-logon event in the samples has SubStatus `0xc000006a` (wrong password), not `0xc0000072` (disabled account), so the rule correctly stays silent. |

### What this tells us
- Tests used attack logs only, so **false-positive rates are unknown**. Benign baseline logs are needed for that.
- **Tuning made from the results:** rule 6 was lowered from `high` to `medium` because log clearing also happens on test machines. Raise it to high when the same host triggers other alerts within an hour.
- Rules 4 and 5 can be bypassed by renamed binaries or other methods. They are one layer of detection, not full coverage.

## Chainsaw note for rule 6
Chainsaw's default mapping for `service: security` only accepts events from the `Microsoft-Windows-Security-Auditing` provider. Event 1102 comes from `Microsoft-Windows-Eventlog`, so it is skipped. Copy `mappings/sigma-event-logs-all.yml` and replace the security block with:
```yaml
    - for:
        logsource.service: security
      filter:
        - Provider: Microsoft-Windows-Security-Auditing
        - Provider: Microsoft-Windows-Eventlog
          int(EventID): 1102
```

## Required logging (otherwise the rules never fire)
- Security log: audit logon failures, security group management, and **Detailed File Share** (success).
- Process creation: **Sysmon** (Event ID 1) or Security 4688 with command-line auditing.

## Known limitations
- Rule 1: the 5-in-5-minutes threshold is a Sigma correlation rule that not every tool supports. Otherwise count in the SIEM.
- Rule 3: Sigma cannot filter by time of day; add an after-hours filter in the SIEM. `PatientRecords` is an assumed share name.

## Reproduce
```bash
pip install sigma-cli
sigma plugin install splunk
sigma check sigma-rules/
sigma convert -t splunk -p splunk_windows sigma-rules/
chainsaw hunt <path-to>/EVTX-ATTACK-SAMPLES -s sigma-rules/ --mapping <path-to>/nilecare-mapping.yml
```
Sample logs: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). Tool: [Chainsaw](https://github.com/WithSecureLabs/chainsaw).

## Incident reports
- [INC-001 - Backup and recovery deletion](incident-reports/INC-001_shadow_copy_deletion.md)
