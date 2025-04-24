import json
from datetime import datetime, timezone
from tabulate import tabulate
from core import log


default_log_type = 'SocketSecurityTool'


class BaseEvent:
    def __init__(self, **kwargs):
        self.Severity = kwargs.get("Severity", "Unknown")
        self.issue_text = kwargs.get("issue_text", "Unknown")
        self.test_name = kwargs.get("test_name", "Unknown")
        self.more_info = kwargs.get("more_info", None)
        self.Message = kwargs.get("Message", "Unknown")
        self.filename = kwargs.get("filename", "Unknown")
        self.URL = kwargs.get("URL", "N/A")
        self.Timestamp = kwargs.get("Timestamp", datetime.now(timezone.utc).isoformat())
        self.Plugin = kwargs.get("Plugin", "Unknown")

    def as_dict(self):
        return dict(self.__dict__)

    def as_row(self):
        return list(self.as_dict().values())

    def render(self, output_type='console'):
        row = self.as_row()
        if output_type == 'markdown':
            return "| " + " | ".join(f"`{str(v)}`" for v in row) + " |"
        elif output_type == 'json':
            return self.as_dict()
        else:
            return " | ".join(str(v) for v in row)


class TrufflehogEvent(BaseEvent):
    def __init__(self, event: dict):
        super().__init__(
            issue_text=event.get("DetectorName", "Unknown Detection"),
            test_name=event.get("SourceName", "Secret Scanning"),
            more_info=event.get("ExtraData", {}).get("rotation_guide", "No remediation guide available"),
            Message=event.get("Raw", "Potential secret detected"),
            FilePath=event.get("file", None),
            Timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            Plugin="Trufflehog",
            Severity="HIGH" if not event.get("Verified", False) else "LOW"
        )
        self.SourceType = event.get("SourceType", "Unknown")
        self.DetectorType = event.get("DetectorType", "Unknown")



class BanditEvent(BaseEvent):
    def __init__(self, event: dict):
        super().__init__(
            issue_text=event.get("issue_text", "Unknown"),
            test_name=event.get("test_name", "Static Analysis"),
            more_info=event.get("more_info", "No remediation guide available"),
            Message=event.get("issue_text", "Unknown issue"),
            FilePath=event.get("filename", "Unknown"),
            Timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            Plugin="Bandit",
            Severity=event.get("issue_severity", "Unknown")
        )
        self.test_id = event.get("test_id", "Unknown")
        self.code = event.get("code", None)
        self.line_number = event.get("line_number", None)
        self.line_range = event.get("line_range", None)


class GosecEvent(BaseEvent):
    def __init__(self, event: dict):
        super().__init__(
            issue_text=event.get("issue_text", "Unknown"),
            test_name=event.get("rule_id", "Unknown"),
            more_info=event.get("cwe", {}).get("url", "No remediation guide available"),
            Message=event.get("details", "Unknown"),
            FilePath=event.get("file", "Unknown"),
            URL=event.get("url", "N/A"),
            Timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            Plugin="Gosec",
            Severity=event.get("severity", "Unknown")
        )
        self.CWE_ID = event.get("cwe", {}).get("id", "Unknown")
        self.code = event.get("code", None)
        self.line_number = event.get("line", None)


class ESLintEvent(BaseEvent):
    def __init__(self, event: dict):
        super().__init__(
            issue_text=event.get("issue_text", "Unknown File"),
            test_name=event.get("rule_id"),
            more_info="Review ESLint rules and fix reported issues",
            Message=f"ESLint detected issues in {event.get('file', 'Unknown')}.",
            FilePath=event.get("file_path", "Unknown"),
            Timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            Plugin="ESLint",
            Severity=event.get("severity", "LOW")
        )
        self.messages = event.get("messages", [])


class TrivyEvent(BaseEvent):
    def __init__(self, event: dict):
        super().__init__(
            issue_text=event.get("Title", ""),
            test_name=event.get("Class", ""),
            more_info=event.get("PrimaryURL", ""),
            Message=f"Trivy scan detected issues in {event.get('PkgID', 'Unknown')}.",
            FilePath=event.get("Target", "Unknown"),
            Timestamp=event.get("PublishedDate", datetime.now(timezone.utc).isoformat()),
            Plugin="Trivy",
            Severity=event.get("severity", "LOW")
        )
        self.CweIDs = event.get("CweIDs", [])


class Console:
    def __init__(self, mode: str = 'console'):
        """
        Initializes the Console client with credentials and HTTP source URL.

        :param mode:
        """

        self.mode = mode

    @staticmethod
    def normalize_events(raw_events: list, plugin: str) -> list:
        events = []
        for event in raw_events:
            if plugin == 'bandit':
                events.append(BanditEvent(event.__dict__))
            elif plugin == 'trufflehog':
                events.append(TrufflehogEvent(event.__dict__))
            elif plugin == 'gosec':
                events.append(GosecEvent(event.__dict__))
            elif plugin == 'eslint':
                events.append(ESLintEvent(event.__dict__))
            elif 'trivy' in plugin:
                events.append(TrivyEvent(event.__dict__))
            else:
                print(f"Unknown event type {plugin}")
        return events

    def print_events(self, events: list, plugin: str) -> None:
        """
        Processes events and outputs them based on the selected output type.

        :param events: List of event objects (subclasses of BaseEvent)
        :param plugin: Optional log type string
        :param output_type: 'console', 'markdown', or 'json'
        :return: Formatted string (markdown/console) or JSON array (str)
        """
        msg = f"No events to process for {plugin} plugin. Skipping output."
        if not events or len(events) == 0:
            print(msg)
            return

        normalized = Console.normalize_events(events, plugin)

        if len(normalized) == 0:
            print(msg)
            return
        print(f"{plugin} issues detected:")
        if self.mode == 'json':
            json_output = [event.render('json') for event in normalized]
            print(json.dumps(json_output, indent=2))
            return

        headers = list(normalized[0].as_dict().keys())
        rows = [event.as_row() for event in normalized]

        if self.mode == 'markdown':
            header_line = "| " + " | ".join(f"`{h}`" for h in headers) + " |"
            divider_line = "| " + " | ".join("---" for _ in headers) + " |"
            body_lines = ["| " + " | ".join(f"`{v}`" for v in row) + " |" for row in rows]
            print("\n".join([header_line, divider_line] + body_lines))
            return

        # Default to console table
        print(tabulate(rows, headers=headers, tablefmt="grid"))

