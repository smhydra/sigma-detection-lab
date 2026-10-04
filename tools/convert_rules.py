#!/usr/bin/env python3
"""
Sigma Multi-Target SIEM Rule Converter
Batch converts repository Sigma rules into Splunk SPL, Elastic ECS/Lucene, and Microsoft Sentinel KQL.
"""

import subprocess
import sys
from pathlib import Path

TARGETS = [
    {"name": "Splunk SPL", "target": "splunk", "pipeline": "splunk_windows", "ext": ".splunk"},
    {"name": "Elastic Lucene", "target": "lucene", "pipeline": "ecs_windows", "ext": ".elastic"},
    {"name": "Microsoft Sentinel KQL", "target": "kusto", "pipeline": None, "ext": ".kql"},
]

def convert_rule(rule_path: Path, target_info: dict, output_dir: Path) -> bool:
    cmd = ["sigma", "convert", "-t", target_info["target"]]
    if target_info.get("pipeline"):
        cmd.extend(["-p", target_info["pipeline"]])
    cmd.append(str(rule_path))

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        converted_query = res.stdout.strip()
        # Remove line header if present
        if converted_query.startswith("Parsing Sigma rules"):
            lines = converted_query.splitlines()
            converted_query = "\n".join(lines[1:]).strip()

        rel_path = rule_path.relative_to(Path("rules"))
        target_out_dir = output_dir / target_info["target"] / rel_path.parent
        target_out_dir.mkdir(parents=True, exist_ok=True)
        
        out_file = target_out_dir / (rule_path.stem + target_info["ext"])
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"// Converted from {rule_path.name} to {target_info['name']}\n")
            f.write(converted_query + "\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [ERROR] {target_info['name']} conversion failed for {rule_path.name}: {e.stderr.strip()}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False

def main():
    rules_dir = Path("rules")
    out_dir = Path("build/converted")
    out_dir.mkdir(parents=True, exist_ok=True)

    rule_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))
    print(f"[*] Found {len(rule_files)} rules to convert across {len(TARGETS)} target backends...")

    success_count = 0
    total_conversions = len(rule_files) * len(TARGETS)

    for rule_file in sorted(rule_files):
        print(f"[*] Processing {rule_file.name}...")
        for target in TARGETS:
            if convert_rule(rule_file, target, out_dir):
                success_count += 1

    print("\n" + "=" * 50)
    print(f"[+] Successfully converted {success_count}/{total_conversions} queries!")
    print(f"[+] Output written to '{out_dir.resolve()}'")

if __name__ == "__main__":
    main()
