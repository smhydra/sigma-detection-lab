# Detection Engineering SOC Tuning & False Positive Mitigation Guide

Detecting threat activity while minimizing alert fatigue requires systematic baseline tuning. This guide details operational best practices for deploying and tuning Sigma rules in production Security Operations Center (SOC) environments.

---

## 1. Tuning Methodology

Alert tuning should follow a structured approach rather than broad exclusions:

```
[ Alert Received ] ➔ [ Analyze Lineage & Context ] ➔ [ Determine Benign Software/Account ] ➔ [ Apply Granular Exclusion Filter ] ➔ [ Document Tuning Rationale ]
```

### 1.1 Exclude by Specific Parent-Child Lineage
*Never* exclude a utility binary globally (e.g., ignoring all `powershell.exe` executions). Always pair the process with its signed parent image, authentic user domain, or explicit command-line flags.

**Bad Exclusion Example**:
```yaml
# DO NOT DO THIS: Suppresses all PowerShell activity
filter:
    Image|endswith: '\powershell.exe'
```

**Good Exclusion Example**:
```yaml
# DO THIS: Excludes only verified internal deployment agent script
filter_sccm:
    ParentImage: 'C:\Windows\CCM\CcmExec.exe'
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '\CCM\Staging\deploy_patch.ps1'
condition: selection and not 1 of filter_*
```

---

## 2. Common False Positive Baselines

### 2.1 Enterprise Management & Deployment Tools
- **Microsoft Intune / SCCM**: Frequently executes encoded PowerShell and script hosts (`CcmExec.exe`, `IntuneManagementExtension.exe`).
- **Software Updaters**: Chrome, Edge, and Zoom installers may invoke `rundll32.exe` or `certutil.exe` from temp paths.

### 2.2 Developer Workstations vs Server Infrastructure
- Separate alert severity by host role:
  - Developer workstation launching `cmd.exe` or `whoami.exe` = **Low / Informational**
  - Production Domain Controller or SQL Server launching `whoami.exe` = **High / Critical**

---

## 3. SIEM-Specific Exclusions

### 3.1 Splunk Exclusion Lookup Table
Maintain an index-level macro or lookup table (e.g., `whitelist_process_lineage.csv`) and join with converted SPL queries:

```splunk
<Sigma_SPL_Query> 
NOT [ search lookup whitelist_process_lineage.csv ]
```

### 3.2 Sentinel / Kusto Custom Watchlists
Integrate Microsoft Sentinel Watchlists for approved administrative user accounts or service principals to dynamically suppress false positives without modifying base detection logic.
