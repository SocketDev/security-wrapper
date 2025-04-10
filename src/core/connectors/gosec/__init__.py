from core.connectors.classes import GosecTestResult
from core import BaseTool
import json


class Gosec(BaseTool):
    result_class = GosecTestResult
    result_key = "Issues"
    default_severities = {"CRITICAL"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "Gosec") -> dict:
        """Processes Gosec output, ensuring compatibility with create_output."""
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }

        results = data.get(cls.result_key, [])
        for entry in results:
            test_result = cls.result_class(**entry, cwd=cwd)
            if test_result.severity.lower() not in cls.default_severities:
                continue
            test_result.plugin_name = plugin_name
            test_result.file = test_result.file  # Ensure compatibility with create_output()

            test_name = cls.get_test_name(test_result)

            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1

            metrics["output"].append(test_result)
            metrics["events"].append(json.dumps(test_result.__dict__))

        return metrics

    @staticmethod
    def get_test_name(test_result):
        return f"Gosec_{test_result.rule_id}_{test_result.severity}"
