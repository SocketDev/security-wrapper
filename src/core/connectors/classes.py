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
        self.target = kwargs.get("Target", "")
        self.Class = kwargs.get("Class", "")
        self.Type = kwargs.get("Type", "")
        self.description = kwargs.get("Description", "")
        self.title = kwargs.get("Title", "")
        self.severity = kwargs.get("Severity", "UNKNOWN")
        self.package = kwargs.get("Package", "Unknown")
        self.file = kwargs.get("File", "Unknown")
        self.url = kwargs.get("URL", "")
        self.issue_text = kwargs.get("IssueText", "")

        # CVSS
        self.cvss_nvd_v2_score = kwargs.get("CVSS", {}).get("nvd", {}).get("V2Score", None)
        self.cvss_nvd_v2_vector = kwargs.get("CVSS", {}).get("nvd", {}).get("V2Vector", "")
        self.cvss_nvd_v3_score = kwargs.get("CVSS", {}).get("nvd", {}).get("V3Score", None)
        self.cvss_nvd_v3_vector = kwargs.get("CVSS", {}).get("nvd", {}).get("V3Vector", "")

        # CWE and IDs
        self.cwe_ids = kwargs.get("CweIDs", [])
        self.vendor_ids = kwargs.get("VendorIDs", [])
        self.vulnerability_id = kwargs.get("VulnerabilityID", "")
        self.status = kwargs.get("Status", "")
        self.severity_source = kwargs.get("SeveritySource", "")
        self.vendor_severity = kwargs.get("VendorSeverity", {})

        # Package data
        self.pkg_id = kwargs.get("PkgID", "")
        self.pkg_name = kwargs.get("PkgName", "")
        self.pkg_identifier = kwargs.get("PkgIdentifier", {})
        self.installed_version = kwargs.get("InstalledVersion", "")
        self.fixed_version = kwargs.get("FixedVersion", "")

        # Dates
        self.published_date = kwargs.get("PublishedDate", "")
        self.last_modified_date = kwargs.get("LastModifiedDate", "")

        # References
        self.references = kwargs.get("References", [])
        self.primary_url = kwargs.get("PrimaryURL", "")

        # Layer metadata
        self.layer_digest = kwargs.get("Layer", {}).get("Digest", "")
        self.layer_diff_id = kwargs.get("Layer", {}).get("DiffID", "")

        # Data source
        data_source = kwargs.get("DataSource", {})
        self.data_source_id = data_source.get("ID", "")
        self.data_source_name = data_source.get("Name", "")
        self.data_source_url = data_source.get("URL", "")

class SocketReachabilityTestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.component = kwargs.get("component", {})
        self.tier1_scan_id = kwargs.get("tier1_scan_id", "")
        self.plugin_name = kwargs.get("plugin_name", "SocketReachability")
        
        # Extract component information from Socket reachability format
        self.name = self.component.get("name", "unknown")
        self.version = self.component.get("version", "unknown") 
        self.ecosystem = self.component.get("type", "npm")  # Changed from "ecosystem" to "type"
        
        # Socket reachability specific fields
        self.license = self.component.get("license", "")
        self.direct = self.component.get("direct", False)
        
        # Handle Socket reachability results - updated to match actual CLI output
        self.vulnerabilities = self.component.get("vulnerabilities", [])
        self.reachability_data = self.component.get("reachability", [])
        
        # Set severity based on reachable vulnerabilities
        self.severity = self._determine_severity()
        self.issue_text = self._generate_issue_text()
        
        # Set file information
        self.file = self._determine_file()
        self.line = 1  # Default line number
        
        super().__init__(**kwargs)

    def _determine_severity(self):
        """Determine severity based on reachable vulnerabilities."""
        if not self.vulnerabilities:
            return "INFO"
        
        # Check for reachable vulnerabilities
        for vuln in self.vulnerabilities:
            reachability_info = vuln.get("reachabilityData", {})
            if reachability_info and not reachability_info.get("undeterminableReachability", True):
                # If we have determinable reachability data, this is likely important
                return "HIGH"
        
        # Check reachability array for any reachable items
        for reach_item in self.reachability_data:
            reachability_list = reach_item.get("reachability", [])
            for reach in reachability_list:
                if reach.get("type") == "reachable":
                    return "HIGH"
        
        return "MEDIUM"

    def _generate_issue_text(self):
        """Generate a description of the reachable issues found."""
        if not self.vulnerabilities and not self.reachability_data:
            return f"Component {self.name}@{self.version} analyzed for reachability - no issues found"
        
        issue_details = []
        
        # Process vulnerabilities with reachability data
        for vuln in self.vulnerabilities:
            ghsa_id = vuln.get("ghsaId", "unknown")
            reachability_info = vuln.get("reachabilityData", {})
            
            if reachability_info:
                pattern = reachability_info.get("pattern", [])
                undeterminable = reachability_info.get("undeterminableReachability", True)
                
                if not undeterminable:
                    issue_detail = f"- Vulnerability {ghsa_id}: Has determinable reachability"
                    if pattern:
                        issue_detail += f" (pattern: {', '.join(pattern)})"
                    issue_details.append(issue_detail)
        
        # Process reachability data
        for reach_item in self.reachability_data:
            ghsa_id = reach_item.get("ghsa_id", "unknown")
            reachability_list = reach_item.get("reachability", [])
            
            for reach in reachability_list:
                if reach.get("type") == "reachable":
                    analysis_level = reach.get("analysisLevel", "unknown")
                    matches = reach.get("matches", [])
                    
                    issue_detail = f"- {ghsa_id}: REACHABLE ({analysis_level} analysis)"
                    
                    # Add match information
                    if matches:
                        match_info = []
                        for match_chain in matches[:2]:  # Limit to first 2 match chains
                            if match_chain and len(match_chain) > 0:
                                first_match = match_chain[0]
                                package = first_match.get("package", "unknown")
                                source_loc = first_match.get("sourceLocation", {})
                                filename = source_loc.get("filename", "unknown")
                                line = source_loc.get("start", {}).get("line", "unknown")
                                confidence = first_match.get("confidence", 0)
                                
                                match_info.append(f"{package} at {filename}:{line} (confidence: {confidence})")
                        
                        if match_info:
                            issue_detail += f"\n  Found in: {'; '.join(match_info)}"
                    
                    issue_details.append(issue_detail)
        
        if not issue_details:
            return f"Component {self.name}@{self.version} analyzed for reachability - no reachable vulnerabilities found"
        
        base_text = f"Socket reachability analysis for {self.name}@{self.version}:"
        return base_text + "\n" + "\n".join(issue_details)

    def _determine_file(self):
        """Determine the file associated with this component."""
        ecosystem = self.ecosystem.lower()
        if ecosystem == "npm" or ecosystem == "node":
            return "package.json"
        elif ecosystem == "pypi" or ecosystem == "python":
            return "requirements.txt"
        elif ecosystem == "go":
            return "go.mod"
        elif ecosystem == "ruby":
            return "Gemfile"
        else:
            return "dependency_manifest"

    def has_reachability_alerts(self):
        """Check if this component has reachable security alerts."""
        # Check if there are vulnerabilities with reachability data
        for vuln in self.vulnerabilities:
            reachability_info = vuln.get("reachabilityData", {})
            if reachability_info and not reachability_info.get("undeterminableReachability", True):
                return True
        
        # Check if there are any reachable items in the reachability data
        for reach_item in self.reachability_data:
            reachability_list = reach_item.get("reachability", [])
            for reach in reachability_list:
                if reach.get("type") == "reachable":
                    return True
        
        return False

    def get_stack_traces_summary(self):
        """Get a formatted summary of all stack traces for this component."""
        if not self.stack_traces:
            return ""
        
        summary = f"Stack traces for {self.name}@{self.version}:\n"
        for i, trace in enumerate(self.stack_traces[:3]):  # Limit to first 3 traces
            summary += f"\nTrace {i+1}:\n"
            if isinstance(trace, list):
                for frame in trace[:5]:  # Limit to first 5 frames per trace
                    summary += f"  at {frame}\n"
                if len(trace) > 5:
                    summary += f"  ... and {len(trace) - 5} more frames\n"
            elif isinstance(trace, str):
                summary += f"  {trace}\n"
        
        if len(self.stack_traces) > 3:
            summary += f"\n... and {len(self.stack_traces) - 3} more traces"
        
        return summary


class SocketSCATestResult(BaseTestResult):
    def __init__(self, **kwargs):
        self.alert = kwargs.get("alert", {})
        self.full_scan_id = kwargs.get("full_scan_id", "")
        self.diff_url = kwargs.get("diff_url", "")
        self.plugin_name = kwargs.get("plugin_name", "SocketSCA")
        
        # Extract alert information from Socket SCA format
        self.package_name = self.alert.get("pkg_name", "unknown")
        self.package_version = self.alert.get("pkg_version", "unknown") 
        self.package_type = self.alert.get("pkg_type", "unknown")
        self.package_id = self.alert.get("pkg_id", "")
        
        # Socket SCA specific fields
        self.alert_type = self.alert.get("type", "unknown")
        self.severity = self.alert.get("severity", "unknown").upper()
        self.description = self.alert.get("description", "")
        self.title = self.alert.get("title", "")
        self.suggestion = self.alert.get("suggestion", "")
        self.next_step_title = self.alert.get("next_step_title", "")
        self.purl = self.alert.get("purl", "")
        self.url = self.alert.get("url", "")
        self.manifests = self.alert.get("manifests", "")
        self.introduced_by = self.alert.get("introduced_by", [])
        
        # Alert properties (props field contains additional context)
        self.props = self.alert.get("props", {})
        
        # Flags
        self.error = self.alert.get("error", False)
        self.warn = self.alert.get("warn", False)
        self.monitor = self.alert.get("monitor", False)
        self.ignore = self.alert.get("ignore", False)
        
        # Generate issue text
        self.issue_text = self._generate_issue_text()
        
        # Set file information based on manifests
        self.file = self._determine_file()
        self.line = 1  # Default line number
        
        super().__init__(**kwargs)

    def _generate_issue_text(self):
        """Generate a description of the Socket SCA alert."""
        base_text = f"Socket SCA Alert: {self.title}"
        
        details = []
        details.append(f"Package: {self.package_name}@{self.package_version} ({self.package_type})")
        details.append(f"Type: {self.alert_type}")
        details.append(f"Severity: {self.severity}")
        
        if self.description:
            details.append(f"Description: {self.description}")
        
        if self.suggestion:
            details.append(f"Suggestion: {self.suggestion}")
        
        if self.url:
            details.append(f"More info: {self.url}")
        
        # Add props information if available
        if self.props:
            if "note" in self.props:
                details.append(f"Note: {self.props['note']}")
            if "notes" in self.props:
                details.append(f"Notes: {self.props['notes']}")
            if "confidence" in self.props:
                details.append(f"Confidence: {self.props['confidence']}")
        
        # Add introduction path
        if self.introduced_by:
            intro_paths = []
            for path in self.introduced_by:
                if isinstance(path, list) and len(path) >= 2:
                    intro_paths.append(f"{path[0]} via {path[1]}")
                elif isinstance(path, list) and len(path) == 1:
                    intro_paths.append(path[0])
                else:
                    intro_paths.append(str(path))
            if intro_paths:
                details.append(f"Introduced by: {', '.join(intro_paths)}")
        
        if self.diff_url:
            details.append(f"Diff URL: {self.diff_url}")
        
        return base_text + "\n" + "\n".join([f"  {detail}" for detail in details])

    def _determine_file(self):
        """Determine the file associated with this alert based on manifests."""
        if self.manifests:
            # Return the first manifest file mentioned
            return self.manifests.split(",")[0].strip()
        
        # Fallback based on package type
        package_type = self.package_type.lower()
        if package_type == "npm":
            return "package.json"
        elif package_type == "pypi":
            return "requirements.txt"
        elif package_type == "go":
            return "go.mod"
        elif package_type == "ruby":
            return "Gemfile"
        else:
            return "dependency_manifest"

    def meets_severity_criteria(self, required_severities):
        """Check if this alert meets the severity criteria."""
        return self.severity in required_severities

    def is_critical_alert(self):
        """Check if this is a critical security alert."""
        return self.severity == "CRITICAL" and self.error
