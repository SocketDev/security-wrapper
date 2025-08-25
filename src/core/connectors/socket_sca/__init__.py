from core.connectors.classes import SocketSCATestResult
from core import BaseTool
import json


class SocketSCA(BaseTool):
    result_class = SocketSCATestResult
    result_key = "new_alerts"
    default_severities = {"CRITICAL", "HIGH"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "SocketSCA") -> dict:
        """Processes Socket SCA scan output and ensures compatibility with create_output."""
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }

        # Check if scan failed
        scan_failed = data.get("scan_failed", False)
        new_alerts = data.get(cls.result_key, [])
        full_scan_id = data.get("full_scan_id", "")
        diff_url = data.get("diff_url", "")
        
        # If scan failed, create a failure result
        if scan_failed:
            failure_result = cls.result_class(
                alert={"type": "scan_failure", "severity": "critical", "description": "Socket SCA scan failed"},
                full_scan_id=full_scan_id,
                diff_url=diff_url,
                cwd=cwd,
                plugin_name=plugin_name
            )
            
            # Always include scan failures regardless of severity filter
            test_name = cls.get_test_name(failure_result)
            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1
            metrics["output"].append(failure_result)
            metrics["events"].append(failure_result)
        
        # Process new alerts
        for alert in new_alerts:
            # Skip empty alerts
            if not alert:
                continue
                
            # Create a test result for each alert
            test_result = cls.result_class(
                alert=alert,
                full_scan_id=full_scan_id,
                diff_url=diff_url,
                cwd=cwd,
                plugin_name=plugin_name
            )

            # Include alerts that meet severity criteria
            if test_result.meets_severity_criteria(cls.default_severities):
                test_name = cls.get_test_name(test_result)

                metrics["tests"].setdefault(test_name, 0)
                metrics["tests"][test_name] += 1

                metrics["output"].append(test_result)
                metrics["events"].append(test_result)

        return metrics

    @staticmethod
    def get_test_name(test_result):
        """Generate a test name based on the Socket SCA analysis."""
        package_name = getattr(test_result, 'package_name', 'unknown')
        alert_type = getattr(test_result, 'alert_type', 'unknown')
        severity = getattr(test_result, 'severity', 'unknown')
        return f"SocketSCA_{package_name}_{alert_type}_{severity}"
