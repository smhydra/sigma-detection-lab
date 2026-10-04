#!/usr/bin/env python3
"""
Sigma Rule Validator & Quality Assurance Tool
Checks rules against Sigma schema specifications, required fields, MITRE ATT&CK tags, and UUID uniqueness.
"""

import sys
import uuid
from pathlib import Path
import yaml

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags"
]

ALLOWED_LEVELS = ["low", "medium", "high", "critical", "informational"]

def validate_rule(file_path: Path, seen_ids: set) -> list[str]:
    errors = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return [f"YAML Parse Error: {e}"]

    if not isinstance(data, dict):
        return ["Invalid YAML root: expected dictionary"]

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"Missing required field: '{field}'")

    # Validate UUID
    rule_id = data.get("id")
    if rule_id:
        try:
            val = uuid.UUID(str(rule_id))
            if str(rule_id) in seen_ids:
                errors.append(f"Duplicate Rule ID: {rule_id}")
            seen_ids.add(str(rule_id))
        except ValueError:
            errors.append(f"Invalid UUID format for 'id': {rule_id}")

    # Validate Severity Level
    level = data.get("level")
    if level and str(level).lower() not in ALLOWED_LEVELS:
        errors.append(f"Invalid level '{level}'. Must be one of {ALLOWED_LEVELS}")

    # Validate Logsource
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if "category" not in logsource and "service" not in logsource:
            errors.append("Logsource missing 'category' or 'service'")
    else:
        errors.append("'logsource' must be a dictionary")

    # Validate Detection & Condition
    detection = data.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("Detection block missing 'condition'")
    else:
        errors.append("'detection' must be a dictionary")

    # Validate MITRE Tags
    tags = data.get("tags", [])
    if isinstance(tags, list):
        if not any(tag.startswith("attack.") for tag in tags):
            errors.append("Rule missing MITRE ATT&CK tags (e.g. 'attack.t1059.001')")
    else:
        errors.append("'tags' must be a list")

    return errors

def main():
    rules_dir = Path("rules")
    if not rules_dir.exists():
        print(f"Error: Rules directory '{rules_dir}' does not exist.")
        sys.exit(1)

    rule_files = list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml"))
    print(f"[*] Validating {len(rule_files)} Sigma rule(s)...")

    total_errors = 0
    seen_ids = set()

    for rule_file in sorted(rule_files):
        errors = validate_rule(rule_file, seen_ids)
        if errors:
            print(f"\n[FAIL] {rule_file}")
            for err in errors:
                print(f"  - {err}")
            total_errors += len(errors)
        else:
            print(f"[PASS] {rule_file}")

    print("\n" + "=" * 50)
    if total_errors == 0:
        print(f"SUCCESS: All {len(rule_files)} rules passed validation!")
        sys.exit(0)
    else:
        print(f"FAILURE: Found {total_errors} error(s) across rules.")
        sys.exit(1)

if __name__ == "__main__":
    main()
