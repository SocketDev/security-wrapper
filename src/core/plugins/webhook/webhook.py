import requests
from typing import Dict, List, Any
from core import log


class Webhook:
    def __init__(self, url: str, headers: dict = None):
        """
        Initializes the Webhook client with URL and optional headers.

        :param url: The webhook URL
        :param headers: Optional headers to include in requests
        """
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def send_consolidated_security_alerts(self, facts_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process consolidated socket facts and send security alerts via webhook.
        
        :param facts_data: Consolidated socket facts data
        :return: A dict with response information
        """
        log.debug("Webhook Plugin Enabled - Processing consolidated security alerts")
        
        # Extract repository and branch information
        repository = facts_data.get("repository", "unknown-repo")
        branch = facts_data.get("branch", "unknown-branch")
        
        # Get new alerts from the facts data
        new_alerts = facts_data.get("new_alerts", [])
        if not new_alerts:
            log.info("No new security alerts to send via webhook")
            return {"status": "success", "message": "No new alerts to process"}
        
        # Extract alerts from facts components
        all_alerts = self._extract_alerts_from_facts(facts_data)
        alerts_to_send = new_alerts if new_alerts else all_alerts
        
        if not alerts_to_send:
            log.info("No security alerts found in facts data")
            return {"status": "success", "message": "No alerts to process"}
        
        log.info(f"Sending {len(alerts_to_send)} security alerts via webhook")
        
        # Create webhook payload
        payload = self._create_webhook_payload_from_consolidated_alerts(alerts_to_send, repository, branch)
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers
            )

            if response.status_code >= 400:
                log.error("Webhook error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent consolidated security alerts via webhook")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send consolidated alerts via webhook: {str(e)}")
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

    def _create_webhook_payload_from_consolidated_alerts(self, alerts: List[Dict[str, Any]], repository: str, branch: str) -> Dict[str, Any]:
        """
        Create webhook payload from consolidated security alerts.
        
        :param alerts: List of security alerts
        :param repository: Repository name
        :param branch: Branch name
        :return: Webhook payload
        """
        # Format alerts for webhook
        formatted_alerts = []
        
        for alert in alerts:
            # Extract alert information
            tool = self._extract_tool_from_purl(alert.get("source", alert.get("component_purl", ""))) or alert.get("tool", alert.get("component_type", "unknown"))
            severity = alert.get("severity", "unknown")
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
            
            # Extract description
            description = (
                props.get("description") or 
                props.get("issue_text") or 
                props.get("details") or 
                props.get("message") or 
                "No description available"
            )

            formatted_alert = {
                "tool": tool,
                "rule_name": rule_name,
                "severity": severity,
                "file": file_path,
                "line": line_number,
                "source": source,
                "description": description,
                "generated_by": alert.get("generatedBy", "unknown"),
                "alert_type": alert.get("type", "unknown"),
                "component_name": alert.get("component_name", "unknown")
            }
            
            # Include any additional properties
            if props:
                formatted_alert["properties"] = props
            
            formatted_alerts.append(formatted_alert)
        
        return {
            "event_type": "security_alerts",
            "repository": repository,
            "branch": branch,
            "total_alerts": len(alerts),
            "alerts": formatted_alerts
        }

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
        Will iterate through events and send to webhook
        :param events: A list containing the events to send
        :param plugin_name: A string of the plugin name
        :return: A dict with response information
        """
        if not events:
            log.debug("No events to send via webhook.")
            return {"status": "no_events"}

        log.debug("Webhook Plugin Enabled")
        
        payload = self.create_webhook_payload_from_events(events, plugin_name)
        log.debug(f"Sending message to {self.url}")
        
        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers
            )

            if response.status_code >= 400:
                log.error("Webhook error %s: %s", response.status_code, response.text)
                return {"status": "error", "message": response.text}
            else:
                log.info("Successfully sent events to webhook")
                return {"status": "success"}
        except Exception as e:
            log.error(f"Failed to send to webhook: {str(e)}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def create_webhook_payload_from_events(events: list, plugin_name: str):
        """
        Creates a webhook payload from a list of events
        """
        payload = {
            "plugin": plugin_name,
            "timestamp": None,  # Will be set by the receiving system if needed
            "events_count": len(events),
            "events": []
        }

        for event in events:
            if hasattr(event, 'as_dict'):
                event_dict = event.as_dict()
            else:
                event_dict = event

            payload["events"].append(event_dict)

        return payload
