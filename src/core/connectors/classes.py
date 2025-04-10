import json
from core import base_github
from datetime import datetime, timezone


class BaseTestResult:
    def __init__(self, **kwargs):
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)

        self.normalize_file_path()
        self.set_url()
        self.set_timestamp()

    def normalize_file_path(self):
        if hasattr(self, 'file') and hasattr(self, 'cwd'):
            self.file = self.file.replace(self.cwd, '').lstrip("./").lstrip("/")
        elif hasattr(self, 'filename') and hasattr(self, 'cwd'):
            self.filename = self.filename.replace(self.cwd, '').lstrip("./").lstrip("/")

    def set_url(self):
        if hasattr(self, 'file') and hasattr(self, 'line'):
            self.url = f"{base_github}/REPO_REPLACE/blob/COMMIT_REPLACE/{self.file}#L{self.line}"
        elif hasattr(self, 'filename') and hasattr(self, 'line_number'):
            self.url = f"{base_github}/REPO_REPLACE/blob/COMMIT_REPLACE/{self.filename}#{self.line_number}"

    def set_timestamp(self):
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " +0000"

    # Add a method to convert the object to a dictionary
    def to_json(self):
        """Convert the object to a dictionary for JSON serialization."""
        return self.__dict__

    # Ensure the object string representation works well with JSON
    def __str__(self):
        return json.dumps(self.to_json())


class BanditTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.code = ""
        self.col_offset = 0
        self.end_col_offset = 0
        self.filename = ""
        self.issue_confidence = ""
        self.issue_cw = {}
        self.issue_severity = ""
        self.issue_text = ""
        self.line_number = 0
        self.line_range = []
        self.more_info = ""
        self.test_id = ""
        self.test_name = ""
        self.url = ""
        self.cwd = ""
        self.timestamp = ""
        self.plugin_name = ""
        super().__init__(**kwargs)


class GosecTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.severity = ""
        self.confidence = ""
        self.cwe = {}
        self.rule_id = ""
        self.details = ""
        self.file = ""
        self.code = ""
        self.line = ""
        self.column = ""
        self.nosec = False
        self.suppressions = ""
        self.cwd = ""
        self.timestamp = ""
        self.plugin_name = ""
        super().__init__(**kwargs)


class TrufflehogTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.SourceMetadata = {}
        self.SourceID = 0
        self.SourceType = 0
        self.SourceName = ""
        self.DetectorType = 0
        self.DetectorName = ""
        self.DecoderName = ""
        self.Verified = False
        self.Raw = ""
        self.RawV2 = ""
        self.Redacted = ""
        self.ExtraData = {}
        self.StructuredData = ""
        self.file = ""
        self.line = 0
        self.cwd = ""
        self.timestamp = ""
        self.plugin_name = ""
        super().__init__(**kwargs)


class ESLintTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.file_path = ""
        self.messages = []
        self.cwd = ""
        self.timestamp = ""
        self.plugin_name = "ESLint"
        self.rule_id = ""
        self.severity = ""
        super().__init__(**kwargs)

    def set_url(self):
        if self.file_path:
            self.url = f"{base_github}/REPO_REPLACE/blob/COMMIT_REPLACE/{self.file_path}"
        else:
            self.url = ""


class TrivyTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.target = ""
        self.type = ""
        self.cwd = ""
        self.timestamp = ""
        self.plugin_name = "Trivy"
        self.file = self.target  # Ensure compatibility with create_output()
        super().__init__(**kwargs)

    def set_url(self):
        if self.target:
            self.url = f"{base_github}/REPO_REPLACE/blob/COMMIT_REPLACE/{self.target}"
        else:
            self.url = ""

class TrivyDockerfileTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.description = kwargs.get("Description", "")
        self.title = kwargs.get("Title", "")
        self.severity = kwargs.get("Severity", "UNKNOWN")
        self.file = kwargs.get("File", "Unknown")
        self.url = kwargs.get("URL", "")
        self.issue_text = kwargs.get("IssueText", "")


class TrivyImageTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.description = kwargs.get("Description", "")
        self.title = kwargs.get("Title", "")
        self.severity = kwargs.get("Severity", "UNKNOWN")
        self.package = kwargs.get("Package", "Unknown")
        self.file = kwargs.get("File", "Unknown")
        self.url = kwargs.get("URL", "")
        self.issue_text = kwargs.get("IssueText", "")
