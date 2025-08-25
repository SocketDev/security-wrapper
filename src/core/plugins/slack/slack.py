import requests
from typing import Dict, List, Any
from core import log


class Slack:
    def __init__(self, webhook_url: str):
        """
        Initializes the Slack client with webhook URL.

        :param webhook_url: The Slack webhook URL
        """
        self.webhook_url = webhook_url

    def send_consolidated_security_alerts(self, facts_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process consolidated socket facts and send security alerts to Slack.
        
        :param facts_data: Consolidated socket facts data
        :return: A dict with response information
        """
        log.debug("Slack Plugin Enabled - Processing consolidated security alerts")
        
        # Extract repository and branch information
        repository = facts_data.get("repository", "unknown-repo")
        branch = facts_data.get("branch", "unknown-branch")
        
        # Get new alerts from the facts data
        new_alerts = facts_data.get("new_alerts", [])
        if not new_alerts:
            log.info("No new security alerts to send to Slack")
            return {"status": "success", "message": "No new alerts to process"}
        
        # Extract alerts from facts components
        all_alerts = self._extract_alerts_from_facts(facts_data)
        alerts_to_send = new_alerts if new_alerts else all_alerts
        
        if not alerts_to_send:
            log.info("No security alerts found in facts data")
            return {"status": "success", "message": "No alerts to process"}
        
        log.info(f"Sending {len(alerts_to_send)} security alerts to Slack")
        
        # Create Slack message blocks
        message_blocks = self._create_slack_blocks_from_consolidated_alerts(alerts_to_send, repository, branch)
        
        try:
            response = requests.post(
                self.webhook_url,
                json={"blocks": message_blocks}
            )

            if response.status_code >= 400:
                log.error("Slack error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent consolidated security alerts to Slack")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send consolidated alerts to Slack: {str(e)}")
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

    def _create_slack_blocks_from_consolidated_alerts(self, alerts: List[Dict[str, Any]], repository: str, branch: str) -> List[Dict[str, Any]]:
        """
        Create Slack message blocks from consolidated security alerts.
        
        :param alerts: List of security alerts
        :param repository: Repository name
        :param branch: Branch name
        :return: List of Slack message blocks
        """
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🔐 *Security Issues Detected in {repository}*\n*Branch:* `{branch}`\n*Total Alerts:* {len(alerts)}"
                }
            },
            {"type": "divider"}
        ]

        for alert in alerts:
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
            line_text = f" (line {line_number})" if line_number else ""
            
            # Extract description
            description = (
                props.get("description") or 
                props.get("issue_text") or 
                props.get("details") or 
                props.get("message") or 
                "No description available"
            )[:150] + ("..." if len(str(description)) > 150 else "")

            # Use emoji based on severity
            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢"
            }.get(severity, "⚠️")

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{severity_emoji} *{rule_name}*\n"
                        f"*Tool:* `{tool}`\n"
                        f"*File:* `{file_path}{line_text}`\n"
                        f"*Severity:* {severity}\n"
                        f"*Source:* `{source}`\n"
                        f"*Description:* {description}"
                    )
                }
            })
            blocks.append({"type": "divider"})

        return blocks

    def send_events(self, events: list, plugin_name: str) -> dict:
        """
        Will iterate through events and send to Slack
        :param events: A list containing the events to send
        :param plugin_name: A string of the plugin name
        :return: A dict with response information
        """
        if not events:
            log.debug("No events to notify via Slack.")
            return {"status": "no_events"}

        log.debug("Slack Plugin Enabled")
        
        message_blocks = self.create_slack_blocks_from_events(events, plugin_name)
        log.debug(f"Sending message to {self.webhook_url}")
        
        try:
            response = requests.post(
                self.webhook_url,
                json={"blocks": message_blocks}
            )

            if response.status_code >= 400:
                log.error("Slack error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent events to Slack")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send to Slack: {str(e)}")
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

    @staticmethod
    def create_slack_blocks_from_events(events: list, plugin_name: str):
        """
        Creates Slack blocks from a list of events
        """
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Security issues found by {plugin_name}*"
                }
            },
            {"type": "divider"}
        ]

        for event in events:
            if hasattr(event, 'as_dict'):
                event_dict = event.as_dict()
            else:
                event_dict = event

            severity = event_dict.get("Severity", "Unknown")
            issue_text = event_dict.get("issue_text", "Unknown")
            test_name = event_dict.get("test_name", "Unknown")
            filename = event_dict.get("filename", "Unknown")
            message = event_dict.get("Message", "Unknown")

            # Use emoji based on severity
            severity_emoji = {
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢",
                "CRITICAL": "🚨"
            }.get(severity.upper(), "⚠️")

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{severity_emoji} *{issue_text}*\n"
                        f"*Test:* `{test_name}`\n"
                        f"*File:* `{filename}`\n"
                        f"*Severity:* {severity}\n"
                        f"*Message:* {message}"
                    )
                }
            })
            blocks.append({"type": "divider"})

        return blocks
