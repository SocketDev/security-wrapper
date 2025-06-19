from datetime import datetime, timezone

class Utils:
    @staticmethod
    def transform_gosec_event(event):
        """Transforms a Gosec security event into the correct Console Output"""
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "SourceComputerId": event.get("cwd", "Unknown"),
            "OperationStatus": event.get("confidence", "Unknown"),
            "Detail": event.get("details", "Unknown"),
            "OperationCategory": "Static Analysis",
            "Solution": event.get("cwe", {}).get("url", "No remediation guide available"),
            "Message": event.get("details", "Unknown"),
            "FilePath": event.get("file", "Unknown"),
            "URL": event.get("url", "N/A"),
            "Timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "Plugin": "Gosec",
            "Severity": event.get("severity", "Unknown"),
            "RuleID": event.get("rule_id", "Unknown"),
            "CWE_ID": event.get("cwe", {}).get("id", "Unknown"),
        }

    @staticmethod
    def transform_bandit_event(event):
        """Transforms a Bandit security event into the correct Sentinel schema."""
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "SourceComputerId": event.get("cwd", "Unknown"),
            "OperationStatus": event.get("issue_severity", "Unknown"),
            "Detail": event.get("issue_text", "Unknown"),
            "OperationCategory": event.get("test_name", "Static Analysis"),
            "Solution": event.get("more_info", "No remediation guide available"),
            "Message": event.get("issue_text", "Unknown issue"),
            "FilePath": event.get("filename", "Unknown"),
            "URL": event.get("url", "N/A"),
            "Timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "Plugin": "Bandit",
            "Severity": event.get("issue_severity", "Unknown"),
            "TestID": event.get("test_id", "Unknown"),
            "CWE_ID": event.get("issue_cwe", {}).get("id", "Unknown"),
            "CWE_Link": event.get("issue_cwe", {}).get("link", "Unknown")
        }

    @staticmethod
    def transform_trufflehog_event(event):
        """Transforms a Trufflehog event into the correct Sentinel schema."""
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "SourceComputerId": event.get("cwd", "Unknown"),
            "OperationStatus": "Success" if event.get("Verified", False) else "Failure",
            "Detail": event.get("DetectorName", "Unknown Detection"),
            "OperationCategory": event.get("SourceName", "Secret Scanning"),
            "Solution": event.get("ExtraData", {}).get("rotation_guide", "No remediation guide available"),
            "Message": event.get("Raw", "Potential secret detected"),
            "FilePath": event.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "Unknown"),
            "Timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "Plugin": "Trufflehog",
            "Severity": "HIGH" if not event.get("Verified", False) else "LOW",
            "SourceType": event.get("SourceType", "Unknown"),
            "DetectorType": event.get("DetectorType", "Unknown")
        }

    @staticmethod
    def transform_eslint_event(event):
        """Transforms an ESLint event into the correct Sentinel schema."""
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "SourceComputerId": event.get("cwd", "Unknown"),
            "OperationStatus": "Success" if event.get("messages") else "Failure",
            "Detail": event.get("file_path", "Unknown File"),
            "OperationCategory": "Linting",
            "Solution": "Review ESLint rules and fix reported issues",
            "Message": f"ESLint detected issues in {event.get('file_path', 'Unknown')}.",
            "FilePath": event.get("file_path", "Unknown"),
            "Timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "Plugin": "ESLint",
            "Severity": "HIGH" if any(msg.get("severity", 1) == 2 for msg in event.get("messages", [])) else "LOW",
            "SourceType": "Linting"
        }

    @staticmethod
    def transform_trivy_event(event):
        """Transforms a Trivy event into the correct Sentinel schema."""
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "SourceComputerId": event.get("cwd", "Unknown"),
            "OperationStatus": "Success" if event.get("Type") else "Failure",
            "Detail": event.get("Target", "Unknown Target"),
            "OperationCategory": "Vulnerability Scanning",
            "Solution": "Check dependencies and apply patches if necessary",
            "Message": f"Trivy scan detected issues in {event.get('Target', 'Unknown')}.",
            "FilePath": event.get("Target", "Unknown"),
            "Timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "Plugin": "Trivy",
            "Severity": "HIGH" if event.get("Type") == "Critical" else "LOW",
            "SourceType": event.get("Type", "Unknown")
        }