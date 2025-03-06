import json
import hashlib
import hmac
import base64
import requests
from datetime import datetime, timezone


default_log_type = 'SocketSecurityTool'


class Sentinel:
    def __init__(self, workspace_id: str, shared_key: str):
        """
        Initializes the Microsoft Sentinel client with credentials and HTTP source URL.

        :param workspace_id: The Microsoft Sentinel Customer ID
        :param shared_key: The Microsoft Sentinel Shared Key
        :param log_type: The Microsoft Sentinel Log Type
        """
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.uri = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    def _generate_signature(self, content_length: int, date: str) -> str:
        """
        Generates the HMAC SHA256 signature required for authentication.

        :param content_length: Length of the request body
        :param date: Current date in RFC 1123 format
        :return: Authorization signature string
        """
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")

        decoded_key = base64.b64decode(self.shared_key)
        hashed_string = hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        signature = base64.b64encode(hashed_string).decode()

        return f"SharedKey {self.workspace_id}:{signature}"

    def send_events(self, events: list, log_type: str = default_log_type) -> list:
        """
        Sends a single event to Microsoft Sentinel.

        :param events: Dictionary representing the event data
        :param log_type:
        :return: Response from the Sentinel API
        """
        errors = []
        events = Sentinel.normalize_events(events, log_type)
        for event in events:
            response = self.send_event(event, log_type)
            if response["status_code"] != 200:
                errors.append(response)
        return errors

    def send_event(self, event_data: dict, log_type: str = default_log_type) -> dict:
        """
        Sends a batch of events to a logging endpoint. This function serializes a
        list of events into JSON format, computes the necessary authorization
        headers, and sends them via an HTTP POST request to the configured logging
        endpoint.

        :param event_data: An event that is serialized to JSON
            and sent to the logging endpoint.
        :type event_data: dict
        :param log_type: The type of log under which the events should be
            categorized. Defaults to the class's `default_log_type`.
        :type log_type: str, optional
        :return: A dictionary with the HTTP response status code and response text
            from the logging endpoint.
        :rtype: dict
        """
        body = json.dumps(
            {
                "detail": event_data,
                "SourceComputerId": "socket-security-tools"
            }
        )
        content_length = len(body)
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        authorization = self._generate_signature(content_length, rfc1123date)

        headers = {
            "Content-Type": "application/json",
            "Authorization": authorization,
            "Log-Type": log_type,
            "x-ms-date": rfc1123date
        }

        response = requests.post(self.uri, data=body, headers=headers)
        return {
            "status_code": response.status_code,
            "response_text": response.text
        }

    @staticmethod
    def transform_gosec_event(event):
        """Transforms a Gosec security event into the correct Sentinel schema."""
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

    @staticmethod
    def normalize_events(events: list, plugin_name: str):
        """Detects event type and normalizes them for Sentinel ingestion."""
        formatted_events = []

        for event in events:
            if isinstance(event, str):
                try:
                    event = json.loads(event)  # Convert from string if necessary
                except json.JSONDecodeError:
                    print(f"Skipping invalid event: {event}")
                    continue  # Skip invalid JSON entries

            if "plugin_name" in event:
                if "bandit" in plugin_name.lower():
                    formatted_events.append(Sentinel.transform_bandit_event(event))
                elif "trufflehog" in plugin_name.lower():
                    formatted_events.append(Sentinel.transform_trufflehog_event(event))
                elif "gosec" in plugin_name.lower():
                    formatted_events.append(Sentinel.transform_gosec_event(event))
        return formatted_events