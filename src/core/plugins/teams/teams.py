import requests
from typing import Dict, List, Any
from core import log


class Teams:
    def __init__(self, webhook_url: str):
        """
        Initializes the Teams client with webhook URL.

        :param webhook_url: The Teams webhook URL
        """
        self.webhook_url = webhook_url

    def send_consolidated_security_alerts(self, facts_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process consolidated socket facts and send security alerts to Microsoft Teams.
        
        :param facts_data: Consolidated socket facts data
        :return: A dict with response information
        """
        log.debug("Teams Plugin Enabled - Processing consolidated security alerts")
        
        # Extract repository and branch information
        repository = facts_data.get("repository", "unknown-repo")
        branch = facts_data.get("branch", "unknown-branch")
        
        # Get new alerts from the facts data
        new_alerts = facts_data.get("new_alerts", [])
        if not new_alerts:
            log.info("No new security alerts to send to Teams")
            return {"status": "success", "message": "No new alerts to process"}
        
        # Extract alerts from facts components
        all_alerts = self._extract_alerts_from_facts(facts_data)
        alerts_to_send = new_alerts if new_alerts else all_alerts
        
        if not alerts_to_send:
            log.info("No security alerts found in facts data")
            return {"status": "success", "message": "No alerts to process"}
        
        log.info(f"Sending {len(alerts_to_send)} security alerts to Teams")
        
        # Create Teams message
        message = self._create_teams_message_from_consolidated_alerts(alerts_to_send, repository, branch)
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message
            )

            if response.status_code >= 400:
                log.error("Teams error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent consolidated security alerts to Teams")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send consolidated alerts to Teams: {str(e)}")
            return {"status": "error", "message": str(e)}

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

    def _create_teams_message_from_consolidated_alerts(self, alerts: List[Dict[str, Any]], repository: str, branch: str) -> Dict[str, Any]:
        """
        Create Teams message from consolidated security alerts.
        
        :param alerts: List of security alerts
        :param repository: Repository name
        :param branch: Branch name
        :return: Teams message payload
        """
        # Create summary section
        facts = [
            {"name": "Repository", "value": repository},
            {"name": "Branch", "value": branch},
            {"name": "Total Alerts", "value": str(len(alerts))}
        ]
        
        # Create sections for each alert
        sections = [
            {
                "activityTitle": f"🔐 Security Issues Detected in {repository}",
                "activitySubtitle": f"Branch: {branch}",
                "facts": facts
            }
        ]
        
        # Add each alert as a section
        for i, alert in enumerate(alerts[:10]):  # Limit to 10 alerts to avoid message size limits
            # Extract alert information
            tool = self._extract_tool_from_purl(alert.get("source", alert.get("component_purl", ""))) or alert.get("tool", alert.get("component_type", "unknown"))
            severity = alert.get("severity", "unknown").upper()
            source = self._clean_purl_source(alert.get("source", alert.get("component_purl", "")))
            
            # Extract rule/test name
            props = alert.get("props", {})
            rule_name = (
                props.get("name") or 
                props.get("test_name") or 
                props.get("rule_id") or 
                alert.get("generatedBy", "unknown")
            )
            
            # Extract file path and line
            location = alert.get("location", {})
            file_path = location.get("file", "unknown")
            line_number = location.get("start") or location.get("line")
            file_location = f"{file_path}" + (f" (line {line_number})" if line_number else "")
            
            # Extract description
            description = (
                props.get("description") or 
                props.get("issue_text") or 
                props.get("details") or 
                props.get("message") or 
                "No description available"
            )[:200] + ("..." if len(str(description)) > 200 else "")

            # Use emoji based on severity
            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢"
            }.get(severity, "⚠️")

            sections.append({
                "activityTitle": f"{severity_emoji} {rule_name}",
                "facts": [
                    {"name": "Tool", "value": tool},
                    {"name": "Severity", "value": severity},
                    {"name": "File", "value": file_location},
                    {"name": "Source", "value": source},
                    {"name": "Description", "value": description}
                ]
            })
        
        if len(alerts) > 10:
            sections.append({
                "activityTitle": f"⚠️ Additional Alerts",
                "facts": [
                    {"name": "Note", "value": f"Showing 10 of {len(alerts)} total alerts. Check full report for complete details."}
                ]
            })
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF5722",  # Red-orange color for security alerts
            "summary": f"Security Issues Detected in {repository}",
            "sections": sections
        }

    def send_events(self, events: list, plugin_name: str) -> dict:
        """
        Will iterate through events and send to Microsoft Teams
        :param events: A list containing the events to send
        :param plugin_name: A string of the plugin name
        :return: A dict with response information
        """
        if not events:
            log.debug("No events to notify via Teams.")
            return {"status": "no_events"}

        log.debug("Teams Plugin Enabled")
        
        message = self.create_teams_message_from_events(events, plugin_name)
        log.debug(f"Sending message to {self.webhook_url}")
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message
            )

            if response.status_code >= 400:
                log.error("Teams error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent events to Teams")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send to Teams: {str(e)}")
            return {"status": "error", "message": str(e)}

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
        Will iterate through events and send to Microsoft Teams
        :param events: A list containing the events to send
        :param plugin_name: A string of the plugin name
        :return: A dict with response information
        """
        if not events:
            log.debug("No events to notify via Teams.")
            return {"status": "no_events"}

        log.debug("Teams Plugin Enabled")
        
        message = self.create_teams_message_from_events(events, plugin_name)
        log.debug(f"Sending message to {self.webhook_url}")
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message
            )

            if response.status_code >= 400:
                log.error("Teams error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent events to Teams")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send to Teams: {str(e)}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def create_teams_message_from_events(events: list, plugin_name: str):
        """
        Creates a Teams message from a list of events
        """
        summary = f"Security issues found by {plugin_name}"
        
        # Create facts array for the message card
        facts = []
        
        for i, event in enumerate(events):
            if hasattr(event, 'as_dict'):
                event_dict = event.as_dict()
            else:
                event_dict = event

            facts.extend([
                {"name": f"Issue #{i+1}", "value": event_dict.get("issue_text", "Unknown")},
                {"name": "Severity", "value": event_dict.get("Severity", "Unknown")},
                {"name": "Test", "value": event_dict.get("test_name", "Unknown")},
                {"name": "File", "value": event_dict.get("filename", "Unknown")},
                {"name": "Message", "value": event_dict.get("Message", "Unknown")[:100] + "..." if len(event_dict.get("Message", "")) > 100 else event_dict.get("Message", "Unknown")}
            ])
            
            # Add separator between events (except for the last one)
            if i < len(events) - 1:
                facts.append({"name": "---", "value": "---"})

        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000",  # Red color for security issues
            "summary": summary,
            "sections": [{
                "activityTitle": summary,
                "activitySubtitle": f"Found {len(events)} security issue(s)",
                "facts": facts
            }]
        }

        return message
