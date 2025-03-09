from core.connectors.classes import TrufflehogTestResult
from core import BaseTool
import json


class Trufflehog(BaseTool):
    result_class = TrufflehogTestResult
    default_severities = {"CRITICAL"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "Trufflehog", show_unverified=False) -> dict:
        """Processes Trufflehog output, ensuring results are extracted correctly."""
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }
        results = data.get("Issues")
        for entry in results:
            if isinstance(entry, str):
                try:
                    entry = json.loads(entry)  # Convert JSON string to dictionary if necessary
                except json.JSONDecodeError:
                    continue  # Skip invalid JSON entries

            if isinstance(entry, dict):
                verified = entry.get("Verified", False)
                if not show_unverified and not verified:
                    continue

                test_result = cls.result_class(**entry, cwd=cwd)

                test_result.plugin_name = plugin_name
                test_result.file = entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                test_result.file = test_result.file.replace(cwd, '').lstrip("/")
                test_result.secret = entry.get("Raw", "")[:6] + "*" * (len(entry.get("Raw", "")) - 6)
                test_result.detection = f"{entry.get('DetectorName', '')} - {entry.get('DecoderName', '')}"
                if verified:
                    test_result.severity = "Critical"
                else:
                    test_result.severity = "Low"
                test_result.use_custom = True
                test_result.issue_text = (
                    f"**Detection:** {test_result.detection}\n"
                    f"**Verified:** `{verified}`\n"
                    f"**Secret:** `{test_result.secret}`"
                    f"Filename: {test_result.file}"
                )
                metrics["output"].append(test_result)
                metrics["events"].append(json.dumps(test_result.__dict__))

        return metrics