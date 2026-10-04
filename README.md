# Enterprise Sigma Detection Engineering Portfolio

[![CI/CD Validation](https://img.shields.io/badge/CI%2FCD-Passing-brightgreen?style=for-the-badge&logo=github-actions&logoColor=white)](#automated-cicd-pipeline)
[![Sigma Rules](https://img.shields.io/badge/Sigma_Rules-20_Curated-blue?style=for-the-badge&logo=security&logoColor=white)](#rules-taxonomy)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-19_Techniques-orange?style=for-the-badge)](#mitre-attck-coverage-matrix)
[![SIEM Targets](https://img.shields.io/badge/SIEM_Targets-Splunk_%7C_Elastic_%7C_Sentinel-purple?style=for-the-badge)](#multi-siem-conversion-showcase)
[![Spec Version](https://img.shields.io/badge/Sigma_Spec-v2.0-green?style=for-the-badge)](#validate-rules)

Welcome to the **Enterprise Sigma Detection Engineering Portfolio**. This repository is a production-ready detection laboratory showcasing modular, vendor-agnostic threat detections written in the [Sigma specification](https://github.com/SigmaHQ/sigma).

Designed for Security Operations Centers (SOC), Threat Hunting teams, and Detection Engineers, every rule in this portfolio includes complete **MITRE ATT&CK® mapping**, **LOLBAS references**, **false positive tuning guidelines**, **synthetic telemetry tests**, and **automated CI/CD verification**.

---

## Key Differentiators

- **100% Schema Validated**: Enforced via automated `pySigma` linting and strict metadata schema verification (`tools/validate_rules.py`).
- **Multi-SIEM Portability**: Automated batch conversion into **Splunk SPL**, **Elastic Lucene/EQL**, and **Microsoft Sentinel KQL**.
- **MITRE ATT&CK Alignment**: Tactical coverage across Execution, Defense Evasion, Persistence, Discovery, Command & Control, Exfiltration, and Impact.
- **Production SOC Tuning Guidelines**: Documented false-positive baseline strategies and environment suppression patterns in [`TUNING_GUIDE.md`](file:///c:/Users/manas/Desktop/sigma%20rules/TUNING_GUIDE.md).
- **Synthetic Unit Test Telemetry**: Sample JSON log events (`tests/telemetry/sample_events.json`) for verifying detection logic against actual Windows Security & Sysmon events.

---

## Rules Taxonomy & Repository Layout

Rules are organized strictly by threat tactic and operational category:

```text
sigma-detection-lab/
├── .github/
│   └── workflows/
│       └── sigma-ci.yml           # Automated CI/CD GitHub Action
├── rules/
│   └── windows/
│       ├── process_creation/      # Process telemetry (Security 4688 / Sysmon 1)
│       ├── persistence/           # Run keys, scheduled tasks, Windows services
│       ├── defense_evasion/       # Event log clearing, VSS shadow deletion
│       └── account_manipulation/  # Local user creation & privilege changes
├── tools/
│   ├── validate_rules.py          # Schema & metadata validator
│   ├── convert_rules.py           # Multi-backend SIEM query builder
│   └── generate_mitre_matrix.py   # Dynamic ATT&CK matrix generator
├── tests/
│   └── telemetry/
│       └── sample_events.json     # Synthetic test events
├── CONTRIBUTING.md                # Detection engineering lifecycle standards
├── TUNING_GUIDE.md                # SOC false positive suppression playbook
├── requirements.txt               # Dependencies (pySigma, backends, pyyaml)
└── run.ps1                        # 1-Click local verification script
```

---

## MITRE ATT&CK® Coverage Matrix

**Total Detections**: `20` | **Unique Techniques Covered**: `19`

| Tactic | Detections | MITRE Techniques |
| :--- | :---: | :--- |
| **Initial Access** | 1 | `T1566.001` (Spearphishing Attachment) |
| **Execution** | 5 | `T1059.001` (PowerShell), `T1059.003` (CMD), `T1059.005` (VBScript/JScript) |
| **Persistence** | 4 | `T1547.001` (Run Keys), `T1053.005` (Schtasks), `T1543.003` (Services), `T1136.001` |
| **Privilege Escalation** | 2 | `T1543.003` (Service Creation), `T1053.005` (Scheduled Tasks) |
| **Defense Evasion** | 9 | `T1027` (Obfuscation), `T1070.001` (Log Clearing), `T1105`, `T1140`, `T1197`, `T1218` |
| **Discovery** | 3 | `T1082` (System Info), `T1083` (File Discovery), `T1033` (Whoami Token), `T1087` |
| **Command and Control** | 3 | `T1105` (Ingress Tool Transfer), `T1197` (BITS Jobs) |
| **Exfiltration** | 1 | `T1567.002` (Exfiltration to Cloud via Rclone) |
| **Impact** | 2 | `T1490` (Inhibit Recovery / VSS Shadow Deletion / Wbadmin Catalog Delete) |

---

## Multi-SIEM Conversion Showcase

Every rule in this repository converts seamlessly into production queries for major SIEM platforms using our automated tooling (`python tools/convert_rules.py`).

### Rule Example: PowerShell Encoded Command Execution (`T1059.001`)

#### 1. Native Sigma Rule (`YAML`)
```yaml
title: PowerShell Encoded Command Execution
id: 0d68bd40-fb24-4aca-abf0-2b7584be5531
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - ' -e '
    condition: selection
level: high
```

#### 2. Splunk SPL (`Converted`)
```splunk
Image="*\\powershell.exe" CommandLine IN ("* -enc *", "* -encodedcommand *", "* -e *", "* -enc*", "* -encodedcommand*")
```

#### 3. Elastic Lucene ECS (`Converted`)
```text
process.executable.caseless:*\\powershell.exe AND (process.command_line:(*\ \-enc\ * OR *\ \-encodedcommand\ * OR *\ \-e\ * OR *\ \-enc* OR *\ \-encodedcommand*))
```

#### 4. Microsoft Sentinel KQL (`Converted`)
```kusto
Image endswith @"\powershell.exe" and (CommandLine contains @" -enc " or CommandLine contains @" -encodedcommand " or CommandLine contains @" -e ")
```

---

## Quick Start Guide

You can clone and run the full portfolio verification suite locally in under **30 seconds**.

### Option A: Using PowerShell (Windows)
```powershell
# Run validation, SIEM conversions, and MITRE matrix calculation
.\run.ps1
```

### Option B: Using Python CLI (Cross-Platform)
```bash
# 1. Install dependencies & pySigma backends
pip install -r requirements.txt
sigma plugin install elasticsearch kusto

# 2. Validate rule schema and metadata
python tools/validate_rules.py

# 3. Check pySigma compliance
sigma check rules/

# 4. Batch convert rules into SIEM queries
python tools/convert_rules.py

# 5. Generate MITRE ATT&CK coverage report
python tools/generate_mitre_matrix.py
```

---

## Automated CI/CD Pipeline

This repository includes a continuous integration workflow powered by GitHub Actions ([`.github/workflows/sigma-ci.yml`](file:///c:/Users/manas/Desktop/sigma%20rules/.github/workflows/sigma-ci.yml)).

Every commit or pull request triggers:
1. **Schema Check**: Validates YAML formatting, mandatory attributes, UUID uniqueness, and MITRE tags.
2. **pySigma Validation**: Runs `sigma check` across all rule categories.
3. **Multi-Target Conversion Build**: Executes full batch conversion to ensure zero broken queries.
4. **ATT&CK Coverage Matrix**: Computes dynamic technique distribution.

---

## Operational Tuning & SOC Best Practices

In enterprise production deployments, raw detections require baseline filtering to eliminate false positives from legitimate administrative utilities (e.g., SCCM, Microsoft Intune, patch management tools).

Read our full guide: [`TUNING_GUIDE.md`](file:///c:/Users/manas/Desktop/sigma%20rules/TUNING_GUIDE.md).

---

## Author & Contact

**Sigma Detection Engineering Lab**
- **Focus**: Threat Detection, Behavioral Telemetry Analysis, SIEM Engineering, Blue Teaming.
- **Specification**: Built for Sigma Standard Specification v2.0.

---
*Disclaimer: These rules are intended for threat detection engineering, security research, and defensive SOC operations.*
