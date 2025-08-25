import requests
from core import log


class Teams:
    def __init__(self, webhook_url: str):
        """
        Initializes the Teams client with webhook URL.

        :param webhook_url: The Teams webhook URL
        """
        self.webhook_url = webhook_url

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
