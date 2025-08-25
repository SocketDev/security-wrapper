import requests
from core import log


class Slack:
    def __init__(self, webhook_url: str):
        """
        Initializes the Slack client with webhook URL.

        :param webhook_url: The Slack webhook URL
        """
        self.webhook_url = webhook_url

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
