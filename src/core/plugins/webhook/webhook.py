import requests
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
