import requests
import base64
import json
from typing import Dict, List, Any, Optional
from core import log


class Jira:
    def __init__(self, config: dict):
        """
        Initializes the Jira client with configuration.

        :param config: Dictionary containing Jira configuration (url, email, api_token, project)
        """
        self.config = config
        self.url = config.get("url")
        self.email = config.get("email")
        self.api_token = config.get("api_token")
        self.project = config.get("project")

    def send_consolidated_security_alerts(self, facts_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process consolidated socket facts and create/update Jira tickets for security issues.
        
        :param facts_data: Consolidated socket facts data
        :return: A dict with response information
        """
        if not self.config.get("enabled", False):
            print("Jira plugin is not enabled")
            return {"status": "disabled"}
        
        print("Jira Plugin Enabled - Processing consolidated security alerts")
        log.debug("Jira Plugin Enabled - Processing consolidated security alerts")
        
        # Extract repository and branch information
        repository = facts_data.get("repository", "unknown-repo")
        branch = facts_data.get("branch", "unknown-branch")
        print(f"Repository: {repository}, Branch: {branch}")
        
        # Create ticket summary
        ticket_summary = f"Socket Security Issues detected in {repository} - {branch}"
        print(f"Ticket summary: {ticket_summary}")
        
        # Check if ticket already exists
        print("Checking for existing tickets...")
        existing_ticket = self._find_existing_ticket(ticket_summary)
        
        # Get all alerts from the facts data
        all_alerts = self._extract_alerts_from_facts(facts_data)
        print(f"Found {len(all_alerts)} total alerts in facts data")
        
        if not all_alerts:
            print("No security alerts found in facts data")
            log.info("No security alerts found in facts data")
            return {"status": "success", "message": "No alerts to process"}
        
        # Get new alerts if we have previous scan data
        new_alerts = facts_data.get("new_alerts", all_alerts)
        print(f"New alerts to process: {len(new_alerts)}")
        
        if existing_ticket:
            # Update existing ticket with new alerts only
            if new_alerts:
                print(f"Found existing ticket {existing_ticket['key']}, adding {len(new_alerts)} new alerts")
                log.info(f"Found existing ticket {existing_ticket['key']}, adding {len(new_alerts)} new alerts")
                return self._add_comment_to_ticket(existing_ticket["key"], new_alerts, repository, branch)
            else:
                print(f"Found existing ticket {existing_ticket['key']}, no new alerts to add")
                log.info(f"Found existing ticket {existing_ticket['key']}, no new alerts to add")
                return {"status": "success", "message": "No new alerts to add", "issue_key": existing_ticket["key"]}
        else:
            # Create new ticket with all alerts
            print(f"Creating new ticket with {len(all_alerts)} security alerts")
            log.info(f"Creating new ticket with {len(all_alerts)} security alerts")
            return self._create_new_ticket(ticket_summary, all_alerts, repository, branch)

    def _find_existing_ticket(self, summary: str) -> Optional[Dict[str, Any]]:
        """
        Search for existing Jira ticket with the given summary.
        
        :param summary: The ticket summary to search for
        :return: Ticket data if found, None otherwise
        """
        try:
            auth = base64.b64encode(f"{self.email}:{self.api_token}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json"
            }
            
            # Search for open tickets in the project
            # We'll filter by summary in the response since JQL exact matching can be tricky
            jql = f'project = "{self.project}" AND status != "Done" AND status != "Closed" AND status != "Resolved" ORDER BY created DESC'
            search_url = f"{self.url}/rest/api/3/search"
            
            params = {
                "jql": jql,
                "fields": "key,summary,status",
                "maxResults": 50  # Get more results to search through
            }
            
            response = requests.get(search_url, headers=headers, params=params)
            if response.status_code == 200:
                search_results = response.json()
                issues = search_results.get("issues", [])
                
                # Filter by exact summary match in the response
                for issue in issues:
                    issue_summary = issue.get("fields", {}).get("summary", "")
                    if issue_summary == summary:
                        log.info(f"Found existing ticket: {issue['key']} with exact summary match")
                        return issue
                
                log.info(f"No existing ticket found with exact summary: {summary}")
            else:
                log.warning(f"Failed to search for existing tickets: {response.status_code} - {response.text}")
                
        except Exception as e:
            log.error(f"Error searching for existing ticket: {str(e)}")
        
        return None

    def _extract_alerts_from_facts(self, facts_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract all alerts from the facts data components.
        
        :param facts_data: Consolidated socket facts data
        :return: List of all alerts
        """
        all_alerts = []
        
        for component in facts_data.get("components", []):
            component_alerts = component.get("alerts", [])
            for alert in component_alerts:
                # Add component context to alert
                alert_with_context = alert.copy()
                alert_with_context["component_name"] = component.get("name", "unknown")
                alert_with_context["component_type"] = component.get("type", "unknown")
                alert_with_context["component_purl"] = component.get("purl", "")
                alert_with_context["tool"] = component.get("type", "unknown")  # Tool is the component type
                alert_with_context["source"] = component.get("purl", "")       # Source is the PURL
                all_alerts.append(alert_with_context)
        
        return all_alerts

    def _create_new_ticket(self, summary: str, alerts: List[Dict[str, Any]], repository: str, branch: str) -> Dict[str, Any]:
        """
        Create a new Jira ticket with security alerts.
        
        :param summary: Ticket summary
        :param alerts: List of security alerts
        :param repository: Repository name
        :param branch: Branch name
        :return: Result dictionary
        """
        auth = base64.b64encode(f"{self.email}:{self.api_token}".encode()).decode()
        
        # Build description in ADF format
        description_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": f"Security issues detected in repository {repository} on branch {branch}:"}
                    ]
                },
                self._create_alerts_table(alerts)
            ]
        }
        
        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary,
                "description": description_adf,
                "issuetype": {"name": "Task"},
                "labels": ["security", "socket-scan", f"repo-{repository}", f"branch-{branch}"]
            }
        }

        auth = base64.b64encode(f"{self.email}:{self.api_token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        
        jira_url = f"{self.url}/rest/api/3/issue"
        
        try:
            print(f"Making Jira API request to: {jira_url}")
            print(f"Project: {self.project}")
            print(f"Summary: {summary}")
            print(f"Email: {self.email}")
            print(f"API Token starts with: {self.api_token[:10]}...")
            
            # First, test authentication by getting project info
            
            # Test project access
            project_url = f"{self.url}/rest/api/3/project/{self.project}"
            print(f"Testing project access: {project_url}")
            test_response = requests.get(project_url, headers=headers)
            print(f"Project access response: {test_response.status_code}")
            
            if test_response.status_code == 200:
                project_data = test_response.json()
                print(f"Project name: {project_data.get('name', 'Unknown')}")
                print(f"Project key: {project_data.get('key', 'Unknown')}")
            else:
                print(f"Project access failed: {test_response.text}")
            
            # Get available issue types for this project
            issue_types_url = f"{self.url}/rest/api/3/issue/createmeta?projectKeys={self.project}"
            print(f"Getting issue types: {issue_types_url}")
            issue_types_response = requests.get(issue_types_url, headers=headers)
            print(f"Issue types response: {issue_types_response.status_code}")
            
            if issue_types_response.status_code == 200:
                meta_data = issue_types_response.json()
                projects = meta_data.get('projects', [])
                if projects:
                    issue_types = projects[0].get('issuetypes', [])
                    print(f"Available issue types: {[it.get('name') for it in issue_types]}")
                    
                    # Use the first available issue type instead of hardcoded "Task"
                    if issue_types:
                        issue_type_name = issue_types[0].get('name', 'Task')
                        print(f"Using issue type: {issue_type_name}")
                        payload["fields"]["issuetype"] = {"name": issue_type_name}
            else:
                print(f"Could not get issue types: {issue_types_response.text}")
                
            response = requests.post(jira_url, json=payload, headers=headers)
            print(f"Jira API response status: {response.status_code}")
            if response.status_code >= 300:
                print(f"Jira error {response.status_code}: {response.text}")
                log.error(f"Jira error {response.status_code}: {response.text}")
                return {"status": "error", "message": response.text}
            else:
                issue_key = response.json().get('key')
                print(f"✅ Jira ticket created successfully: {issue_key}")
                log.info(f"Jira ticket created: {issue_key}")
                return {"status": "success", "issue_key": issue_key, "created": True}
        except Exception as e:
            print(f"❌ Failed to create Jira ticket: {str(e)}")
            log.error(f"Failed to create Jira ticket: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _add_comment_to_ticket(self, issue_key: str, new_alerts: List[Dict[str, Any]], repository: str, branch: str) -> Dict[str, Any]:
        """
        Add a comment with new alerts to an existing ticket.
        
        :param issue_key: Jira ticket key
        :param new_alerts: List of new security alerts
        :param repository: Repository name
        :param branch: Branch name
        :return: Result dictionary
        """
        auth = base64.b64encode(f"{self.email}:{self.api_token}".encode()).decode()
        
        # Build comment in ADF format
        comment_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": f"New security issues detected ({len(new_alerts)} alerts):"}
                    ]
                },
                self._create_alerts_table(new_alerts)
            ]
        }
        
        payload = {
            "body": comment_adf
        }

        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        
        comment_url = f"{self.url}/rest/api/3/issue/{issue_key}/comment"
        
        try:
            response = requests.post(comment_url, json=payload, headers=headers)
            if response.status_code >= 300:
                log.error(f"Jira comment error {response.status_code}: {response.text}")
                return {"status": "error", "message": response.text}
            else:
                log.info(f"Added comment to Jira ticket: {issue_key}")
                return {"status": "success", "issue_key": issue_key, "comment_added": True}
        except Exception as e:
            log.error(f"Failed to add comment to Jira ticket: {str(e)}")
            return {"status": "error", "message": str(e)}

    def _create_alerts_table(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create an ADF table from security alerts with consistent formatting.
        
        :param alerts: List of security alerts
        :return: ADF table structure
        """
        def make_cell(text):
            return {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": str(text) if text is not None else ""}]
                    }
                ]
            }

        # Header row with consistent columns
        header_row = {
            "type": "tableRow",
            "content": [
                make_cell("Tool"),
                make_cell("Rule/Test Name"),
                make_cell("Severity"),
                make_cell("File"),
                make_cell("Line"),
                make_cell("Source"),
                make_cell("Description")
            ]
        }

        rows = [header_row]

        for alert in alerts:
            # Extract alert information with consistent field mapping
            tool = self._extract_tool_from_purl(alert.get("source", alert.get("component_purl", ""))) or alert.get("tool", alert.get("component_type", "unknown"))
            rule_name = self._extract_rule_name(alert)
            severity = alert.get("severity", "unknown").upper()
            file_path = self._extract_file_path(alert)
            line_number = self._extract_line_number(alert)
            source = self._clean_purl_source(alert.get("source", alert.get("component_purl", "")))
            description = self._extract_description(alert)

            row = {
                "type": "tableRow",
                "content": [
                    make_cell(tool),
                    make_cell(rule_name),
                    make_cell(severity),
                    make_cell(file_path),
                    make_cell(line_number),
                    make_cell(source),
                    make_cell(description)
                ]
            }
            rows.append(row)

        return {
            "type": "table",
            "content": rows
        }

    def _get_tool_type_display(self, alert_type: str) -> str:
        """Convert alert type to user-friendly tool display name."""
        type_mapping = {
            "external-sast-python": "sast-python",
            "external-sast-golang": "sast-golang", 
            "external-sast-javascript": "sast-javascript",
            "external-secrets": "secrets",
            "external-container-image": "container-image",
            "external-container-dockerfile": "container-dockerfile",
            "external-socket-sca": "socket-sca"
        }
        return type_mapping.get(alert_type, alert_type)

    def _extract_rule_name(self, alert: Dict[str, Any]) -> str:
        """Extract rule/test name from alert."""
        props = alert.get("props", {})
        return (
            props.get("name") or 
            props.get("test_name") or 
            props.get("rule_id") or 
            alert.get("generatedBy", "unknown")
        )

    def _extract_file_path(self, alert: Dict[str, Any]) -> str:
        """Extract file path from alert."""
        location = alert.get("location", {})
        return location.get("file", "unknown")

    def _extract_line_number(self, alert: Dict[str, Any]) -> str:
        """Extract line number from alert."""
        location = alert.get("location", {})
        line = location.get("start") or location.get("line")
        return str(line) if line is not None else ""

    def _extract_description(self, alert: Dict[str, Any]) -> str:
        """Extract description from alert."""
        props = alert.get("props", {})
        return (
            props.get("description") or 
            props.get("issue_text") or 
            props.get("details") or 
            props.get("message") or 
            "No description available"
        )[:200] + ("..." if len(str(props.get("description", ""))) > 200 else "")

    def _extract_tool_from_purl(self, purl: str) -> str:
        """Extract tool type from PURL's type parameter."""
        if not purl or "?type=" not in purl:
            return ""
        
        try:
            # Extract the type parameter from the PURL
            # Format: pkg:ecosystem/name@version?type=tool-type
            type_part = purl.split("?type=")[1]
            # Handle multiple parameters by taking only the first one
            tool_type = type_part.split("&")[0]
            return tool_type
        except (IndexError, AttributeError):
            return ""

    def _clean_purl_source(self, purl: str) -> str:
        """Clean PURL by removing type parameter and empty query string."""
        if not purl:
            return ""
        
        try:
            # Remove the type parameter
            if "?type=" in purl:
                # Split on ?type= and take the first part
                base_purl = purl.split("?type=")[0]
                
                # Check if there are other parameters after type=
                type_section = purl.split("?type=")[1]
                if "&" in type_section:
                    # There are other parameters, reconstruct with remaining params
                    remaining_params = "&".join(type_section.split("&")[1:])
                    return f"{base_purl}?{remaining_params}"
                else:
                    # No other parameters, return clean base PURL
                    return base_purl
            else:
                # No type parameter, return as is
                return purl
        except (IndexError, AttributeError):
            return purl

    def send_events(self, events: list, plugin_name: str) -> dict:
        """
        Will iterate through events and send to Jira as issues
        :param events: A list containing the events to send
        :param plugin_name: A string of the plugin name to use for the issue title
        :return: A dict with response information
        """
        if not self.config.get("enabled", False):
            return {"status": "disabled"}
        
        log.debug("Jira Plugin Enabled")
        
        # Create a summary of all events
        summary = f"Security Issues found from {plugin_name}"
        
        # Build description in ADF format
        description_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": f"Security issues were found by {plugin_name}:"}
                    ]
                },
                self.create_adf_table_from_events(events)
            ]
        }
        
        log.debug("Sending Jira Issue")
        
        # Build and send the Jira issue
        auth = base64.b64encode(
            f"{self.email}:{self.api_token}".encode()
        ).decode()

        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary,
                "description": description_adf,
                "issuetype": {"name": "Task"}
            }
        }

        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        
        jira_url = f"{self.url}/rest/api/3/issue"
        log.debug(f"Jira URL: {jira_url}")
        
        try:
            response = requests.post(jira_url, json=payload, headers=headers)
            if response.status_code >= 300:
                log.error(f"Jira error {response.status_code}: {response.text}")
                return {"status": "error", "message": response.text}
            else:
                issue_key = response.json().get('key')
                log.info(f"Jira ticket created: {issue_key}")
                return {"status": "success", "issue_key": issue_key}
        except Exception as e:
            log.error(f"Failed to send to Jira: {str(e)}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def create_adf_table_from_events(events):
        """
        Creates an ADF (Atlassian Document Format) table from a list of events
        """
        def make_cell(text):
            return {
                "type": "tableCell",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": str(text)}]
                    }
                ]
            }

        # Header row
        header_row = {
            "type": "tableRow",
            "content": [
                make_cell("Severity"),
                make_cell("Issue"),
                make_cell("Test Name"),
                make_cell("File"),
                make_cell("Message")
            ]
        }

        rows = [header_row]

        for event in events:
            if hasattr(event, 'as_dict'):
                event_dict = event.as_dict()
            else:
                event_dict = event

            row = {
                "type": "tableRow",
                "content": [
                    make_cell(event_dict.get("Severity", "Unknown")),
                    make_cell(event_dict.get("issue_text", "Unknown")),
                    make_cell(event_dict.get("test_name", "Unknown")),
                    make_cell(event_dict.get("filename", "Unknown")),
                    make_cell(event_dict.get("Message", "Unknown"))
                ]
            }
            rows.append(row)

        return {
            "type": "table",
            "content": rows
        }
