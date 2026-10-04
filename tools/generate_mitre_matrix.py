#!/usr/bin/env python3
"""
MITRE ATT&CK Matrix & Coverage Generator
Extracts MITRE ATT&CK tags from Sigma rules and generates a formatted Markdown matrix table.
"""

from pathlib import Path
import yaml

TACTIC_NAMES = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact"
}

def main():
    rules_dir = Path("rules")
    rule_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))

    tactic_map = {}
    technique_map = {}
    rule_count = 0

    for rule_file in rule_files:
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rule_count += 1
            title = data.get("title", rule_file.stem)
            tags = data.get("tags", [])

            rule_tactics = []
            rule_techniques = []

            for tag in tags:
                if not tag.startswith("attack."):
                    continue
                code = tag.split(".")[1]
                if code.startswith("t") and code[1:].replace(".", "").isdigit():
                    tech_id = code.upper()
                    rule_techniques.append(tech_id)
                elif code in TACTIC_NAMES:
                    rule_tactics.append(TACTIC_NAMES[code])

            for tech in rule_techniques:
                if tech not in technique_map:
                    technique_map[tech] = []
                technique_map[tech].append((title, rule_file.name))

            for tac in rule_tactics:
                if tac not in tactic_map:
                    tactic_map[tac] = 0
                tactic_map[tac] += 1

        except Exception as e:
            print(f"Error reading {rule_file}: {e}")

    print("## MITRE ATT&CK® Detection Coverage Matrix\n")
    print(f"**Total Rules Analyzed**: `{rule_count}` | **Unique Techniques Covered**: `{len(technique_map)}`\n")

    print("| Tactic | Covered Rules |")
    print("| :--- | :---: |")
    for tac, name in TACTIC_NAMES.items():
        tac_title = TACTIC_NAMES[tac]
        cnt = tactic_map.get(tac_title, 0)
        status = f"**{cnt} rules**" if cnt > 0 else "0 rules"
        print(f"| {tac_title} | {status} |")

    print("\n### Detailed Technique Mapping\n")
    print("| Technique ID | Detection Rule Title | Rule File |")
    print("| :--- | :--- | :--- |")
    for tech_id in sorted(technique_map.keys()):
        for title, fname in technique_map[tech_id]:
            print(f"| `{tech_id}` | {title} | `{fname}` |")

if __name__ == "__main__":
    main()
