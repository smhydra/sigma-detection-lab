# Detection Engineering Contribution Guidelines

Thank you for contributing to this Detection Engineering repository! To ensure all rules maintain enterprise-grade quality and seamless portability, please follow the standards outlined below.

---

## 1. Rule Lifecycle & Standards

Every Sigma detection rule in this repository undergoes a 5-stage engineering lifecycle:

```
[ Research & Threat Modeling ] ➔ [ Rule Authoring (Sigma v2.0) ] ➔ [ Baseline & False Positive Tuning ] ➔ [ Automated CI Validation ] ➔ [ SIEM Deployment ]
```

### 1.1 Naming Convention
Rules must be named using lower-snake-case following the pattern:
`<category>_<technique_or_binary>_<description>.yml`

*Examples*:
- `powershell_encoded_command.yml`
- `certutil_decode_or_urlcache.yml`
- `vssadmin_shadow_delete.yml`

### 1.2 Mandatory Fields
All rules submitted via Pull Request must include the following schema fields:

| Field | Description | Format / Example |
| :--- | :--- | :--- |
| `title` | Clear, concise description of the threat | `PowerShell Encoded Command Execution` |
| `id` | Unique UUID v4 string | `0d68bd40-fb24-4aca-abf0-2b7584be5531` |
| `status` | Lifecycle status | `experimental` or `stable` |
| `description` | Technical summary of adversary activity | `Detects PowerShell launched with base64...` |
| `author` | Author name or handle | `Sigma Detection Lab` |
| `date` | YYYY-MM-DD creation date | `2026-10-04` |
| `references` | Authoritative threat intel / MITRE links | Array of URLs (LOLBAS, MITRE ATT&CK) |
| `tags` | MITRE ATT&CK tactic & technique mappings | `attack.execution`, `attack.t1059.001` |
| `logsource` | Telemetry mapping | `category: process_creation`, `product: windows` |
| `detection` | Selection logic and `condition` | Selection map + condition string |
| `falsepositives` | Known benign triggers and tuning advice | Array of string notes |
| `level` | Severity assessment | `low`, `medium`, `high`, `critical` |

---

## 2. Testing & PR Requirements

Before submitting a Pull Request:
1. Run local validation:
   ```powershell
   .\run.ps1
   ```
2. Verify that all rules pass `tools/validate_rules.py` with zero errors.
3. Ensure SIEM conversions build cleanly in Splunk SPL, Elastic Lucene, and Microsoft Sentinel KQL.
4. Add synthetic telemetry samples in `tests/telemetry/sample_events.json` matching your new detection logic.
