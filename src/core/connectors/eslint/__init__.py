from core.connectors.classes import ESLintTestResult
from core import BaseTool
import json
from collections import defaultdict


class ESLint(BaseTool):
    result_class = ESLintTestResult
    default_severities = {"CRITICAL"}  # Default severities to include
    default_rule_severities = {
        "security/detect-eval-with-expression": "CRITICAL",
        "security/detect-non-literal-require": "CRITICAL",
        "security/detect-non-literal-fs-filename": "CRITICAL",
        "security/detect-buffer-noassert": "HIGH",
        "security/detect-new-buffer": "HIGH",
        "security/detect-unsafe-regex": "HIGH",
        "security/detect-disable-mustache-escape": "HIGH",
        "security/detect-no-csrf-before-method-override": "MEDIUM",
        "security/detect-pseudoRandomBytes": "MEDIUM",
        "security/detect-possible-timing-attacks": "MEDIUM",
        "security/detect-bidi-characters": "LOW",
        "security/detect-child-process": "LOW",
        "security/detect-non-literal-regexp": "LOW",
        "security/detect-object-injection": "LOW",
        "@typescript-eslint/no-implied-eval": "CRITICAL",
        "@typescript-eslint/no-throw-literal": "CRITICAL",
        "@typescript-eslint/no-misused-promises": "CRITICAL",
        "@typescript-eslint/no-unsafe-argument": "CRITICAL",
        "@typescript-eslint/no-unsafe-assignment": "CRITICAL",
        "@typescript-eslint/no-unsafe-call": "CRITICAL",
        "@typescript-eslint/no-unsafe-member-access": "CRITICAL",
        "@typescript-eslint/no-unsafe-return": "CRITICAL",
        "@typescript-eslint/ban-ts-comment": "HIGH",
        "@typescript-eslint/no-explicit-any": "HIGH",
        "@typescript-eslint/explicit-module-boundary-types": "HIGH",
        "@typescript-eslint/no-floating-promises": "HIGH",
        "@typescript-eslint/no-for-in-array": "HIGH",
        "@typescript-eslint/no-misused-new": "HIGH",
        "@typescript-eslint/no-non-null-asserted-optional-chain": "HIGH",
        "@typescript-eslint/no-non-null-assertion": "HIGH",
        "@typescript-eslint/no-unnecessary-type-assertion": "HIGH",
        "@typescript-eslint/prefer-optional-chain": "HIGH",
        "@typescript-eslint/prefer-nullish-coalescing": "HIGH",
        "@typescript-eslint/restrict-plus-operands": "HIGH",
        "@typescript-eslint/restrict-template-expressions": "HIGH",
        "@typescript-eslint/require-await": "HIGH",
        "@typescript-eslint/unbound-method": "HIGH",
        "@typescript-eslint/array-type": "MEDIUM",
        "@typescript-eslint/ban-types": "MEDIUM",
        "@typescript-eslint/consistent-type-assertions": "MEDIUM",
        "@typescript-eslint/consistent-type-definitions": "MEDIUM",
        "@typescript-eslint/explicit-function-return-type": "MEDIUM",
        "@typescript-eslint/no-empty-interface": "MEDIUM",
        "@typescript-eslint/no-inferrable-types": "MEDIUM",
        "@typescript-eslint/no-invalid-void-type": "MEDIUM",
        "@typescript-eslint/no-redeclare": "MEDIUM",
        "@typescript-eslint/no-shadow": "MEDIUM",
        "@typescript-eslint/no-unused-vars": "MEDIUM",
        "@typescript-eslint/no-use-before-define": "MEDIUM",
        "@typescript-eslint/prefer-as-const": "MEDIUM"
    }

    @classmethod
    def process_output(cls, data: list, cwd: str, plugin_name: str = "ESLint", return_json: bool = False,
                       severities: set = None, rule_severities: dict = None, repo: str = "REPO_REPLACE",
                       commit: str = "COMMIT_REPLACE") -> dict:
        """Processes ESLint output, consolidating repeated file occurrences and formatting properly."""
        if severities is None:
            severities = cls.default_severities
        if rule_severities is None:
            rule_severities = cls.default_rule_severities

        metrics = {"tests": {}, "severities": {}, "output": [], "events": []}
        file_issues = defaultdict(lambda: defaultdict(list))

        for entry in data:
            file_path = entry.get("filePath", "Unknown").replace(cwd, "").lstrip("./")
            if not entry.get("messages"):
                continue

            for message in entry["messages"]:
                rule_id = message.get("ruleId", "Unknown Rule")
                normalized_rule_id = rule_id.split("/")[-1]
                severity = rule_severities.get(rule_id, rule_severities.get(normalized_rule_id, "LOW"))
                if severity not in severities:
                    continue

                file_issues[file_path][rule_id].append(message.get("line", "N/A"))

        for file, rules in file_issues.items():
            for rule_id, lines in rules.items():
                file_link = f"**Filename:** [{file}](https://github.com/{repo}/blob/{commit}/{file})"
                line_links = "\n".join(
                    [f"* [Line {line}](https://github.com/{repo}/blob/{commit}/{file}#L{line})" for line in
                     sorted(set(lines))])

                issue_text = f"**Rule:** `{rule_id}`\n**Severity:** `{rule_severities.get(rule_id, 'LOW')}`\n{file_link}\n**Instances ({len(lines)}):**\n{line_links}"

                test_result = cls.result_class(
                    file=file,
                    rule_id=rule_id,
                    severity=rule_severities.get(rule_id, "LOW"),
                    issue_text=issue_text,
                    cwd=cwd
                )
                test_result.plugin_name = plugin_name

                test_name = cls.get_test_name(test_result)
                metrics["tests"].setdefault(test_name, 0)
                metrics["tests"][test_name] += 1
                metrics["output"].append(test_result)
                metrics["events"].append(json.dumps(test_result.__dict__))

        return json.dumps(metrics, indent=2) if return_json else metrics

    @staticmethod
    def get_test_name(test_result):
        return f"ESLint_{test_result.rule_id}"
