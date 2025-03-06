from core.connectors.classes import BanditTestResult
from core import BaseTool
import json


class Bandit(BaseTool):
    result_class = BanditTestResult
    result_key = "results"
    default_severities = {"CRITICAL"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "Bandit") -> dict:
        """Processes Bandit output and ensures compatibility with create_output."""
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }

        results = data.get(cls.result_key, [])
        for entry in results:
            test_result = cls.result_class(**entry, cwd=cwd)
            test_result.plugin_name = plugin_name
            test_result.file = test_result.filename  # Ensure compatibility with create_output()

            test_name = cls.get_test_name(test_result)

            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1

            metrics["output"].append(test_result)
            metrics["events"].append(json.dumps(test_result.__dict__))

        return metrics

    @staticmethod
    def get_test_name(test_result):
        return f"Bandit_{test_result.test_id}_{test_result.issue_severity}"
