"""
Socket Facts Consolidator

This module consolidates results from various security tools (SAST, Secret Scanning, 
Container Scanning, etc.) into a unified .socket.facts.json format. This allows all 
tool results to be processed consistently by the runner.

The format follows the Socket Facts schema with an "alerts" extension for non-package 
security findings like SAST issues, secrets, and container vulnerabilities.

Git Repository Information:
The consolidator automatically adds repository information to the facts file including:
- repository: The repository name
- branch: The current branch or "detached-head" for CI environments
- scan_timestamp: ISO 8601 timestamp of when the scan was performed

Environment Variable Overrides:
- SOCKET_REPOSITORY_NAME or GITHUB_REPOSITORY: Override repository name
- SOCKET_BRANCH_NAME, GITHUB_REF_NAME, GITHUB_HEAD_REF: Override branch name

S3 Storage Support:
Optional S3-compatible storage for facts files with change detection:
- SOCKET_S3_ENABLED: Set to 'true' to enable S3 storage
- SOCKET_S3_BUCKET: S3 bucket name
- SOCKET_S3_ACCESS_KEY: S3 access key
- SOCKET_S3_SECRET_KEY: S3 secret key
- SOCKET_S3_ENDPOINT: S3 endpoint (defaults to AWS S3)
- SOCKET_S3_REGION: S3 region (defaults to us-east-1)

Files are stored as: bucket/repo/branch/.socket.facts.json
The consolidator compares with previous scans and identifies new alerts.

GitHub Actions Support:
The consolidator handles detached HEAD states common in CI environments and
automatically extracts repository/branch information from GitHub Actions
environment variables when available.
"""

import json
import os
import subprocess
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

try:
    from light_s3_client import Client
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False


class SocketFactsConsolidator:
    """Consolidates security tool results into Socket Facts format."""
    
    def __init__(self, workspace_path: str = "."):
        self.workspace_path = workspace_path
        self.consolidated_facts = {
            "components": []
        }
        # S3 configuration
        self.s3_enabled = self._is_s3_enabled()
        self.s3_client = self._init_s3_client() if self.s3_enabled else None
        self.s3_bucket = os.environ.get('SOCKET_S3_BUCKET', 'security-wrapper')
        self.s3_endpoint = os.environ.get('SOCKET_S3_ENDPOINT')
    
    def _is_s3_enabled(self) -> bool:
        """Check if S3 upload is enabled and properly configured."""
        return (
            S3_AVAILABLE and
            bool(os.environ.get('SOCKET_S3_ENABLED', '').lower() in ('true', '1', 'yes')) and
            bool(os.environ.get('SOCKET_S3_BUCKET')) and
            bool(os.environ.get('SOCKET_S3_ACCESS_KEY')) and
            bool(os.environ.get('SOCKET_S3_SECRET_KEY'))
        )
    
    def _init_s3_client(self) -> Optional[Any]:
        """Initialize S3 client if enabled and available."""
        if not S3_AVAILABLE:
            return None
        
        try:
            endpoint = os.environ.get('SOCKET_S3_ENDPOINT')
            region = os.environ.get('SOCKET_S3_REGION', 'us-east-1')
            access_key = os.environ.get('SOCKET_S3_ACCESS_KEY')
            secret_key = os.environ.get('SOCKET_S3_SECRET_KEY')
            
            if endpoint:
                # Use server parameter for custom endpoints (like MinIO) but still provide region
                return Client(
                    server=endpoint,
                    region=region,
                    access_key=access_key,
                    secret_key=secret_key
                )
            else:
                # Use region for AWS S3 (default)
                return Client(
                    region=region,
                    access_key=access_key,
                    secret_key=secret_key
                )
        except Exception as e:
            print(f"Warning: Failed to initialize S3 client: {e}")
            return None
    
    def load_existing_socket_facts(self, facts_file_path: str = ".socket.facts.json") -> Dict[str, Any]:
        """Load existing socket facts file if it exists."""
        try:
            with open(facts_file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"components": []}
    
    def _get_git_repository_info(self) -> Dict[str, Any]:
        """Get git repository information including repo name, branch, and timestamp."""
        repo_info = {}
        
        # Check for environment variable overrides first
        env_repo = os.environ.get('SOCKET_REPOSITORY_NAME') or os.environ.get('GITHUB_REPOSITORY')
        env_branch = os.environ.get('SOCKET_BRANCH_NAME') or os.environ.get('GITHUB_REF_NAME')
        
        # Get repository name
        if env_repo:
            # For GITHUB_REPOSITORY, extract just the repo name (owner/repo -> repo)
            repo_info["repository"] = env_repo.split('/')[-1] if '/' in env_repo else env_repo
        else:
            # Try to get from git remote
            try:
                result = subprocess.run(
                    ["git", "remote", "get-url", "origin"],
                    cwd=self.workspace_path,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    remote_url = result.stdout.strip()
                    # Extract repo name from URL (handles both SSH and HTTPS)
                    if remote_url:
                        # Remove .git suffix if present
                        if remote_url.endswith('.git'):
                            remote_url = remote_url[:-4]
                        # Extract repo name from the end of the URL
                        repo_name = remote_url.split('/')[-1]
                        repo_info["repository"] = repo_name
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                # Git command failed or git not available - this is OK
                pass
        
        # Get branch name
        if env_branch:
            repo_info["branch"] = env_branch
        else:
            # Try to get from git
            try:
                # First try to get the current branch
                result = subprocess.run(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=self.workspace_path,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    branch = result.stdout.strip()
                    # Handle detached HEAD state (common in CI/GitHub Actions)
                    if branch == "HEAD":
                        # Try to get the branch from GitHub environment variables
                        if os.environ.get('GITHUB_HEAD_REF'):  # For pull requests
                            repo_info["branch"] = os.environ.get('GITHUB_HEAD_REF')
                        elif os.environ.get('GITHUB_REF'):  # For pushes
                            github_ref = os.environ.get('GITHUB_REF')
                            if github_ref.startswith('refs/heads/'):
                                repo_info["branch"] = github_ref.replace('refs/heads/', '')
                            else:
                                repo_info["branch"] = "detached-head"
                        else:
                            repo_info["branch"] = "detached-head"
                    else:
                        repo_info["branch"] = branch
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                # Git command failed or git not available - this is OK
                pass
        
        # Add scan timestamp
        repo_info["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
        
        return repo_info
    
    def _get_s3_key(self, repository: str, branch: str) -> str:
        """Generate S3 key in format: repo/branch/.socket.facts.json"""
        return f"{repository}/{branch}/.socket.facts.json"
    
    def _download_previous_facts(self, repository: str, branch: str) -> Optional[Dict[str, Any]]:
        """Download previous facts file from S3 if it exists."""
        if not self.s3_enabled or not self.s3_client:
            return None
        
        try:
            s3_key = self._get_s3_key(repository, branch)
            # Use download_file method and read from temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='r', delete=True) as temp_file:
                success = self.s3_client.download_file(self.s3_bucket, s3_key, temp_file.name)
                if success:
                    with open(temp_file.name, 'r') as f:
                        content = f.read()
                    return json.loads(content)
                else:
                    return None
        except Exception as e:
            print(f"Info: No previous facts file found in S3 or error downloading: {e}")
            return None
    
    def _upload_facts_to_s3(self, facts: Dict[str, Any], repository: str, branch: str) -> bool:
        """Upload facts file to S3."""
        if not self.s3_enabled or not self.s3_client:
            return False
        
        try:
            s3_key = self._get_s3_key(repository, branch)
            facts_json = json.dumps(facts, indent=2)
            
            # Convert to bytes for upload
            facts_bytes = facts_json.encode('utf-8')
            
            success = self.s3_client.upload_fileobj(facts_bytes, self.s3_bucket, s3_key)
            
            if success:
                print(f"Successfully uploaded facts to S3: s3://{self.s3_bucket}/{s3_key}")
                return True
            else:
                print(f"Failed to upload facts to S3")
                return False
        except Exception as e:
            print(f"Error uploading facts to S3: {e}")
            return False
    
    def _find_new_alerts(self, current_facts: Dict[str, Any], previous_facts: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find new alerts by comparing current facts with previous facts."""
        if not previous_facts:
            # If no previous facts, all alerts are new
            return self._extract_all_alerts(current_facts)
        
        current_alerts = self._extract_all_alerts(current_facts)
        previous_alerts = self._extract_all_alerts(previous_facts)
        
        # Create a set of previous alert signatures for comparison
        previous_signatures = set()
        for alert in previous_alerts:
            signature = self._create_alert_signature(alert)
            previous_signatures.add(signature)
        
        # Find new alerts
        new_alerts = []
        for alert in current_alerts:
            signature = self._create_alert_signature(alert)
            if signature not in previous_signatures:
                new_alerts.append(alert)
        
        return new_alerts
    
    def _extract_all_alerts(self, facts: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all alerts from facts components."""
        all_alerts = []
        for component in facts.get("components", []):
            component_alerts = component.get("alerts", [])
            for alert in component_alerts:
                # Add component context to alert
                alert_with_context = alert.copy()
                alert_with_context["component_name"] = component.get("name", "unknown")
                alert_with_context["component_type"] = component.get("type", "unknown")
                all_alerts.append(alert_with_context)
        return all_alerts
    
    def _create_alert_signature(self, alert: Dict[str, Any]) -> str:
        """Create a unique signature for an alert to enable comparison."""
        # Use key fields that uniquely identify an alert
        signature_parts = [
            alert.get("type", ""),
            alert.get("title", ""),
            alert.get("description", ""),
            alert.get("component_name", ""),
            str(alert.get("manifestFiles", [])),  # Convert to string for hashing
        ]
        return "|".join(signature_parts)
    
    def consolidate_all_results(self, temp_output_dir: str = ".") -> Dict[str, Any]:
        """Consolidate all security tool results into a single socket facts format."""
        # Start with existing socket facts (from Socket tools)
        socket_facts_path = os.path.join(self.workspace_path, ".socket.facts.json")
        consolidated = self.load_existing_socket_facts(socket_facts_path)
        
        # Add git repository information at the top level
        repo_info = self._get_git_repository_info()
        consolidated.update(repo_info)
        
        # Process Socket vulnerabilities and reachability data into alerts
        self._process_socket_vulnerabilities(consolidated)
        
        # Get repository and branch for S3 operations
        repository = consolidated.get("repository", "unknown-repo")
        branch = consolidated.get("branch", "unknown-branch")
        
        # Download previous facts from S3 if enabled
        previous_facts = None
        if self.s3_enabled:
            previous_facts = self._download_previous_facts(repository, branch)
        
        # Add external security findings as synthetic components with alerts
        external_components = []
        
        # Process SAST results
        external_components.extend(self._process_bandit_results(temp_output_dir))
        external_components.extend(self._process_gosec_results(temp_output_dir))
        external_components.extend(self._process_eslint_results(temp_output_dir))
        
        # Process Secret Scanning results
        external_components.extend(self._process_trufflehog_results(temp_output_dir))
        
        # Process Container Scanning results
        external_components.extend(self._process_trivy_results(temp_output_dir))
        
        # Process Socket SCA results
        external_components.extend(self._process_socket_sca_results(temp_output_dir))
        
        # Add external components to consolidated facts
        if external_components:
            consolidated["components"].extend(external_components)
        
        # Find new alerts if we have previous facts
        if previous_facts:
            new_alerts = self._find_new_alerts(consolidated, previous_facts)
            consolidated["new_alerts"] = new_alerts
            consolidated["new_alerts_count"] = len(new_alerts)
            print(f"Found {len(new_alerts)} new alerts since last scan")
        else:
            # No previous facts - all alerts are considered new
            all_alerts = []
            for component in consolidated.get("components", []):
                all_alerts.extend(component.get("alerts", []))
            consolidated["new_alerts"] = all_alerts
            consolidated["new_alerts_count"] = len(all_alerts)
            print(f"No previous facts found - all {len(all_alerts)} alerts are considered new")
        
        # Upload current facts to S3 if enabled
        if self.s3_enabled:
            self._upload_facts_to_s3(consolidated, repository, branch)
        
        return consolidated

    def _process_socket_vulnerabilities(self, consolidated: Dict[str, Any]):
        """Process Socket vulnerabilities and reachability data into alerts format."""
        components_with_vulnerabilities = 0
        total_alerts_added = 0
        
        for component in consolidated.get("components", []):
            vulnerabilities = component.get("vulnerabilities", [])
            reachability_data = component.get("reachability", [])
            
            if not vulnerabilities:
                continue
                
            components_with_vulnerabilities += 1
            component_alerts = []
            
            # Keep the original ecosystem type (npm, pypi, etc.) for Socket components
            # per the constraint that Socket Reachability and SCA should use ecosystem types
            original_type = component.get("type", "unknown")
            
            # Add qualifiers to indicate this is Socket-processed data
            if "qualifiers" not in component:
                component["qualifiers"] = {}
            component["qualifiers"]["socket_processed"] = True
            component["qualifiers"]["has_vulnerability_data"] = True
            
            # Create reachability lookup for faster access
            reachability_lookup = {}
            for reach in reachability_data:
                ghsa_id = reach.get("ghsa_id")
                if ghsa_id:
                    reachability_lookup[ghsa_id] = reach
            
            # Process each vulnerability
            for vuln in vulnerabilities:
                ghsa_id = vuln.get("ghsaId")
                if not ghsa_id:
                    continue
                
                # Get reachability info for this vulnerability
                reachability_info = reachability_lookup.get(ghsa_id, {})
                reachability_matches = reachability_info.get("reachability", [])
                
                # Check if vulnerability is reachable
                is_reachable = any(
                    reach.get("type") == "reachable" 
                    for reach in reachability_matches
                )
                
                # Create alert for this vulnerability using the original ecosystem type
                alert = {
                    "type": original_type,  # Keep ecosystem type (npm, pypi, etc.)
                    "severity": "high" if is_reachable else "medium",  # Reachable vulns are higher severity
                    "generatedBy": "socket",
                    "props": {
                        "name": ghsa_id,
                        "description": f"Vulnerability {ghsa_id} in {component.get('name', 'unknown')} {component.get('version', 'unknown')}",
                        "pkgName": component.get("name", "unknown"),
                        "installedVersion": component.get("version", "unknown"),
                        "range": vuln.get("range", "unknown"),
                        "reachable": is_reachable,
                        "vulnerability_details": {
                            "ghsa_id": ghsa_id,
                            "range": vuln.get("range", "unknown"),
                            "reachability_pattern": vuln.get("reachabilityData", {}).get("pattern", []),
                            "undeterminable_reachability": vuln.get("reachabilityData", {}).get("undeterminableReachability", False)
                        },
                        "reachabilityData": vuln.get("reachabilityData", {}) if is_reachable else None
                    },
                    "location": {
                        "files": component.get("manifestFiles", [])
                    }
                }
                
                # Add reachability match details if available
                if is_reachable and reachability_matches:
                    alert["props"]["reachabilityMatches"] = reachability_matches
                
                component_alerts.append(alert)
                total_alerts_added += 1
            
            # Add alerts to component
            if component_alerts:
                component["alerts"] = component.get("alerts", []) + component_alerts
        
        print(f"DEBUG: Processing {len(consolidated.get('components', []))} components for Socket reachability")
        print(f"DEBUG: Found {components_with_vulnerabilities} components with vulnerabilities")
        print(f"DEBUG: Found {len([c for c in consolidated.get('components', []) if c.get('reachability')])} components with reachability data")
        print(f"DEBUG: Including {components_with_vulnerabilities} components in results")

    def _process_bandit_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process Bandit SAST results into socket facts format."""
        bandit_file = os.path.join(temp_output_dir, "bandit_output.json")
        if not os.path.exists(bandit_file):
            return []
        
        try:
            with open(bandit_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        
        results = data.get("results", [])
        if not results:
            return []
        
        # Group by file to create components with file as qualifier
        file_components = {}
        
        for issue in results:
            filename = issue.get("filename", "unknown")
            # Normalize filename relative to workspace
            if filename.startswith("./"):
                filename = filename[2:]
            
            if filename not in file_components:
                file_components[filename] = {
                    "id": str(uuid.uuid4()),
                    "type": "generic",  # Generic type for SAST
                    "name": f"sast-bandit-{filename.replace('/', '-')}",
                    "version": "1.0.0",
                    "purl": f"pkg:generic/sast-bandit@1.0.0",
                    "direct": True,
                    "dev": False,
                    "manifestFiles": [{"file": filename, "start": 1, "end": 1}],
                    "qualifiers": {
                        "file": filename,
                        "tool": "bandit",
                        "scan_type": "sast"
                    },
                    "alerts": []
                }
            
            # Create alert for this issue with code block in properties
            alert = {
                "type": "generic",
                "severity": self._map_bandit_severity(issue.get("issue_severity", "UNKNOWN")),
                "generatedBy": "bandit",
                "props": {
                    "name": issue.get("test_name", "unknown"),
                    "description": issue.get("issue_text", ""),
                    "test_id": issue.get("test_id", ""),
                    "confidence": issue.get("issue_confidence", ""),
                    "cwe": issue.get("issue_cwe", {}),
                    "more_info": issue.get("more_info", ""),
                    "code_block": {
                        "start_line": issue.get("line_number", 1),
                        "end_line": issue.get("line_number", 1),
                        "column_start": issue.get("col_offset", 0),
                        "column_end": issue.get("end_col_offset", 0),
                        "code": issue.get("code", "")
                    }
                },
                "location": {
                    "file": filename,
                    "start": issue.get("line_number", 1),
                    "end": issue.get("line_number", 1),
                    "column_start": issue.get("col_offset", 0),
                    "column_end": issue.get("end_col_offset", 0)
                }
            }
            
            file_components[filename]["alerts"].append(alert)
        
        return list(file_components.values())
    
    def _process_gosec_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process Gosec SAST results into socket facts format."""
        gosec_file = os.path.join(temp_output_dir, "gosec_output.json")
        if not os.path.exists(gosec_file):
            return []
        
        try:
            with open(gosec_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        
        issues = data.get("Issues", [])
        if not issues:
            return []
        
        # Group by file to create components with file as qualifier
        file_components = {}
        
        for issue in issues:
            filename = issue.get("file", "unknown")
            # Normalize filename relative to workspace
            if filename.startswith("./"):
                filename = filename[2:]
            
            if filename not in file_components:
                file_components[filename] = {
                    "id": str(uuid.uuid4()),
                    "type": "generic",  # Generic type for SAST
                    "name": f"sast-gosec-{filename.replace('/', '-')}",
                    "version": "1.0.0",
                    "purl": f"pkg:generic/sast-gosec@1.0.0",
                    "direct": True,
                    "dev": False,
                    "manifestFiles": [{"file": filename, "start": 1, "end": 1}],
                    "qualifiers": {
                        "file": filename,
                        "tool": "gosec",
                        "scan_type": "sast"
                    },
                    "alerts": []
                }
            
            # Create alert for this issue with code block in properties
            alert = {
                "type": "generic",
                "severity": self._map_gosec_severity(issue.get("severity", "UNKNOWN")),
                "generatedBy": "gosec",
                "props": {
                    "name": issue.get("rule_id", "unknown"),
                    "description": issue.get("details", ""),
                    "confidence": issue.get("confidence", ""),
                    "cwe": issue.get("cwe", {}),
                    "nosec": issue.get("nosec", False),
                    "code_block": {
                        "start_line": int(issue.get("line", 1)),
                        "end_line": int(issue.get("line", 1)),
                        "column_start": int(issue.get("column", 0)),
                        "column_end": int(issue.get("column", 0)),
                        "code": issue.get("code", "")
                    }
                },
                "location": {
                    "file": filename,
                    "start": int(issue.get("line", 1)),
                    "end": int(issue.get("line", 1)),
                    "column_start": int(issue.get("column", 0)),
                    "column_end": int(issue.get("column", 0))
                }
            }
            
            file_components[filename]["alerts"].append(alert)
        
        return list(file_components.values())
    
    def _process_eslint_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process ESLint SAST results into socket facts format."""
        eslint_file = os.path.join(temp_output_dir, "eslint_output.json")
        if not os.path.exists(eslint_file):
            return []
        
        try:
            with open(eslint_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        
        if not isinstance(data, list):
            return []
        
        # Group by file to create components with file as qualifier
        file_components = {}
        
        for file_result in data:
            filename = file_result.get("filePath", "unknown")
            # Normalize filename relative to workspace
            if filename.startswith("./"):
                filename = filename[2:]
            
            messages = file_result.get("messages", [])
            if not messages:
                continue
            
            if filename not in file_components:
                file_components[filename] = {
                    "id": str(uuid.uuid4()),
                    "type": "generic",  # Generic type for SAST
                    "name": f"sast-eslint-{filename.replace('/', '-')}",
                    "version": "1.0.0",
                    "purl": f"pkg:generic/sast-eslint@1.0.0",
                    "direct": True,
                    "dev": False,
                    "manifestFiles": [{"file": filename, "start": 1, "end": 1}],
                    "qualifiers": {
                        "file": filename,
                        "tool": "eslint",
                        "scan_type": "sast"
                    },
                    "alerts": []
                }
            
            for message in messages:
                # Only process error-level issues
                if message.get("severity", 0) < 2:
                    continue
                
                alert = {
                    "type": "generic",
                    "severity": "medium",  # ESLint errors are typically medium severity
                    "generatedBy": "eslint",
                    "props": {
                        "name": message.get("ruleId", "unknown"),
                        "description": message.get("message", ""),
                        "nodeType": message.get("nodeType", ""),
                        "source": message.get("source", ""),
                        "code_block": {
                            "start_line": message.get("line", 1),
                            "end_line": message.get("endLine", message.get("line", 1)),
                            "column_start": message.get("column", 0),
                            "column_end": message.get("endColumn", message.get("column", 0)),
                            "code": message.get("source", "")
                        }
                    },
                    "location": {
                        "file": filename,
                        "start": message.get("line", 1),
                        "end": message.get("endLine", message.get("line", 1)),
                        "column_start": message.get("column", 0),
                        "column_end": message.get("endColumn", message.get("column", 0))
                    }
                }
                
                file_components[filename]["alerts"].append(alert)
        
        return list(file_components.values())
    
    def _process_trufflehog_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process Trufflehog secret scanning results into socket facts format."""
        trufflehog_file = os.path.join(temp_output_dir, "trufflehog_output.json")
        if not os.path.exists(trufflehog_file):
            print("DEBUG: Trufflehog output file not found")
            return []
        
        try:
            # Trufflehog outputs NDJSON format
            secrets = []
            with open(trufflehog_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            secrets.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            print(f"DEBUG: Loaded {len(secrets)} secrets from Trufflehog")
        except FileNotFoundError:
            print("DEBUG: Trufflehog file not found during processing")
            return []
        
        if not secrets:
            return []
        
        # Group by file to create components with file as qualifier
        file_components = {}
        
        for secret in secrets:
            source_metadata = secret.get("SourceMetadata", {})
            data = source_metadata.get("Data", {})
            filename = data.get("Filesystem", {}).get("file", "unknown")
            line_number = data.get("Filesystem", {}).get("line", 1)
            
            # Normalize filename relative to workspace
            if filename.startswith("/workspace/"):
                filename = filename[11:]  # Remove /workspace/ prefix
            elif filename.startswith("./"):
                filename = filename[2:]
            
            # Skip if filename is still absolute or unknown
            if filename.startswith("/") or filename == "unknown":
                continue
            
            if filename not in file_components:
                file_components[filename] = {
                    "id": str(uuid.uuid4()),
                    "type": "generic",  # Generic type for secrets
                    "name": f"secrets-trufflehog-{filename.replace('/', '-')}",
                    "version": "1.0.0",
                    "purl": f"pkg:generic/secrets-trufflehog@1.0.0",
                    "direct": True,
                    "dev": False,
                    "manifestFiles": [{"file": filename, "start": 1, "end": 1}],
                    "qualifiers": {
                        "file": filename,
                        "tool": "trufflehog",
                        "scan_type": "secrets"
                    },
                    "alerts": []
                }
            
            # Create alert for this secret
            alert = {
                "type": "generic",
                "severity": "high",  # Secrets are typically high severity
                "generatedBy": "trufflehog",
                "props": {
                    "name": secret.get("DetectorName", "unknown"),
                    "description": f"Secret detected: {secret.get('DetectorName', 'unknown')} in {filename}",
                    "verified": secret.get("Verified", False),
                    "detector_type": secret.get("DetectorType", ""),
                    "source_name": secret.get("SourceName", ""),
                    "raw_preview": secret.get("Raw", "")[:50] + "..." if len(secret.get("Raw", "")) > 50 else secret.get("Raw", ""),
                    "code_block": {
                        "start_line": line_number,
                        "end_line": line_number,
                        "code": secret.get("Raw", "")[:100] + "..." if len(secret.get("Raw", "")) > 100 else secret.get("Raw", "")
                    }
                },
                "location": {
                    "file": filename,
                    "start": line_number,
                    "end": line_number
                }
            }
            
            file_components[filename]["alerts"].append(alert)
        
        print(f"DEBUG: Processed {len(secrets)} Trufflehog secrets into {len(file_components)} components")
        return list(file_components.values())

    def _process_trivy_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process Trivy container and dockerfile scanning results into socket facts format."""
        components = []
        
        # Process Trivy image scan results
        import glob
        for trivy_file in glob.glob(os.path.join(temp_output_dir, "trivy_image_*.json")):
            components.extend(self._process_single_trivy_file(trivy_file, "container-trivy"))
        
        # Process Trivy dockerfile scan results
        for trivy_file in glob.glob(os.path.join(temp_output_dir, "trivy_dockerfile_*.json")):
            components.extend(self._process_single_trivy_file(trivy_file, "dockerfile-trivy"))
        
        return components
    
    def _process_single_trivy_file(self, trivy_file: str, scan_type: str) -> List[Dict[str, Any]]:
        """Process a single Trivy result file."""
        try:
            with open(trivy_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        
        results = data.get("Results", [])
        if not results:
            return []
        
        components = []
        filename = os.path.basename(trivy_file)
        
        for result in results:
            target = result.get("Target", filename)
            vulnerabilities = result.get("Vulnerabilities", [])
            misconfigurations = result.get("Misconfigurations", [])
            
            if not vulnerabilities and not misconfigurations:
                continue
            
            component = {
                "id": str(uuid.uuid4()),
                "type": "generic",  # Generic type for container scanning
                "name": f"trivy-scan-{target.replace('/', '-').replace(':', '-')}",
                "version": "1.0.0",
                "purl": f"pkg:generic/trivy@1.0.0",
                "direct": True,
                "dev": False,
                "manifestFiles": [{"file": target, "start": 1, "end": 1}],
                "qualifiers": {
                    "target": target,
                    "tool": "trivy",
                    "scan_type": scan_type.replace("-trivy", "")  # container or dockerfile
                },
                "alerts": []
            }
            
            # Process vulnerabilities
            for vuln in vulnerabilities:
                alert = {
                    "type": "generic",
                    "severity": self._map_trivy_severity(vuln.get("Severity", "UNKNOWN")),
                    "generatedBy": "trivy",
                    "props": {
                        "name": vuln.get("VulnerabilityID", "unknown"),
                        "description": vuln.get("Description", ""),
                        "pkgName": vuln.get("PkgName", ""),
                        "installedVersion": vuln.get("InstalledVersion", ""),
                        "fixedVersion": vuln.get("FixedVersion", ""),
                        "references": vuln.get("References", []),
                        "vulnerability_details": {
                            "package": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "vulnerability_id": vuln.get("VulnerabilityID", "")
                        }
                    },
                    "location": {
                        "file": target
                    }
                }
                component["alerts"].append(alert)
            
            # Process misconfigurations
            for misconf in misconfigurations:
                alert = {
                    "type": "generic",
                    "severity": self._map_trivy_severity(misconf.get("Severity", "UNKNOWN")),
                    "generatedBy": "trivy",
                    "props": {
                        "name": misconf.get("ID", "unknown"),
                        "description": misconf.get("Description", ""),
                        "title": misconf.get("Title", ""),
                        "message": misconf.get("Message", ""),
                        "resolution": misconf.get("Resolution", ""),
                        "references": misconf.get("References", []),
                        "code_block": {
                            "start_line": misconf.get("CauseMetadata", {}).get("StartLine", 1),
                            "end_line": misconf.get("CauseMetadata", {}).get("EndLine", 1),
                            "code": misconf.get("CauseMetadata", {}).get("Code", "")
                        }
                    },
                    "location": {
                        "file": target,
                        "start": misconf.get("CauseMetadata", {}).get("StartLine", 1),
                        "end": misconf.get("CauseMetadata", {}).get("EndLine", 1)
                    }
                }
                component["alerts"].append(alert)
            
            if component["alerts"]:
                components.append(component)
        
        return components
    
    def _process_socket_sca_results(self, temp_output_dir: str) -> List[Dict[str, Any]]:
        """Process Socket SCA results into socket facts format."""
        socket_sca_file = os.path.join(temp_output_dir, "socket_sca_output.json")
        if not os.path.exists(socket_sca_file):
            return []
        
        try:
            with open(socket_sca_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        
        # Check if scan failed
        if data.get("scan_failed", False):
            return [{
                "id": str(uuid.uuid4()),
                "type": "generic",  # Generic type for scan failures
                "name": "socket-sca-scan-failed",
                "version": "1.0.0",
                "purl": "pkg:generic/socket-sca-scan@1.0.0",
                "direct": True,
                "dev": False,
                "manifestFiles": [{"file": ".", "start": 1, "end": 1}],
                "qualifiers": {
                    "tool": "socket-sca",
                    "scan_type": "sca",
                    "status": "failed"
                },
                "alerts": [{
                    "type": "generic",
                    "severity": "critical",
                    "generatedBy": "socket-sca",
                    "props": {
                        "name": "scan-failure",
                        "description": data.get("error", "Socket SCA scan failed"),
                        "scan_failed": True
                    },
                    "location": {"file": "."}
                }]
            }]
        
        new_alerts = data.get("new_alerts", [])
        if not new_alerts:
            return []
        
        # Group alerts by package/ecosystem
        package_components = {}
        
        for alert in new_alerts:
            package_name = alert.get("package", "unknown")
            ecosystem = alert.get("ecosystem", "unknown")  # e.g., npm, pypi, etc.
            version = alert.get("version", "unknown")
            
            # Use package name + ecosystem as the key to properly group
            component_key = f"{ecosystem}:{package_name}"
            
            if component_key not in package_components:
                # For Socket SCA, use the actual ecosystem type (npm, pypi, etc.)
                # instead of generic, following the constraint that Socket types should be ecosystem types
                component_type = ecosystem if ecosystem != "unknown" else "generic"
                
                # Create proper PURL for real packages
                if ecosystem != "unknown" and package_name != "unknown":
                    purl = f"pkg:{ecosystem}/{package_name}@{version}"
                else:
                    purl = f"pkg:generic/socket-sca-{package_name}@1.0.0"
                
                package_components[component_key] = {
                    "id": str(uuid.uuid4()),
                    "type": component_type,  # Use ecosystem type for Socket SCA/Reachability
                    "name": package_name,
                    "version": version,
                    "purl": purl,
                    "direct": True,
                    "dev": False,
                    "manifestFiles": [{"file": alert.get("file", "unknown"), "start": 1, "end": 1}],
                    "qualifiers": {
                        "tool": "socket-sca",
                        "scan_type": "sca",
                        "ecosystem": ecosystem
                    },
                    "alerts": []
                }
            
            socket_alert = {
                "type": component_type if ecosystem != "unknown" else "generic",
                "severity": self._map_socket_sca_severity(alert.get("severity", "unknown")),
                "generatedBy": "socket-sca",
                "props": {
                    "name": alert.get("type", "unknown"),
                    "description": alert.get("description", ""),
                    "category": alert.get("category", ""),
                    "subcategory": alert.get("subcategory", ""),
                    "package_details": {
                        "package": package_name,
                        "ecosystem": ecosystem,
                        "version": version
                    }
                },
                "location": {
                    "file": alert.get("file", "unknown")
                }
            }
            
            package_components[component_key]["alerts"].append(socket_alert)
        
        return list(package_components.values())
    
    def _map_bandit_severity(self, severity: str) -> str:
        """Map Bandit severity to standard levels."""
        severity_map = {
            "HIGH": "critical",
            "MEDIUM": "high", 
            "LOW": "medium"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _map_gosec_severity(self, severity: str) -> str:
        """Map Gosec severity to standard levels."""
        severity_map = {
            "HIGH": "critical",
            "MEDIUM": "high",
            "LOW": "medium"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _map_trivy_severity(self, severity: str) -> str:
        """Map Trivy severity to standard levels."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _map_socket_sca_severity(self, severity: str) -> str:
        """Map Socket SCA severity to standard levels."""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium", 
            "LOW": "low"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def save_consolidated_facts(self, output_path: str = ".socket.facts.json") -> None:
        """Save the consolidated facts to file."""
        consolidated = self.consolidate_all_results()
        with open(output_path, 'w') as f:
            json.dump(consolidated, f, indent=2)
