import os
from core.plugins.sumologic import Sumologic
from core.plugins.microsoft_sentinel import Sentinel
from core.plugins.console import Console
from core.plugins.jira import Jira
from core.plugins.slack import Slack
from core.plugins.teams import Teams
from core.plugins.webhook import Webhook


def load_sumo_logic_plugin():
    """
    Loads the Sumologic plugin if it is enabled and properly configured.

    :return: Instance of the Sumologic class or None if not enabled/configured.
    """
    sumo_logic_enabled = os.getenv("INPUT_SUMO_LOGIC_ENABLED", "false").lower() == "true"
    if not sumo_logic_enabled:
        # print("Sumo Logic integration is disabled.")
        return None

    sumo_logic_http_source_url = os.getenv("INPUT_SUMO_LOGIC_HTTP_SOURCE_URL")

    if not all([sumo_logic_http_source_url]):
        print("Sumo Logic environment variables are not properly configured!")
        return None

    return Sumologic(sumo_logic_http_source_url)

def load_ms_sentinel_plugin():
    """
    Loads the Microsoft Sentinel plugin if it is enabled and properly configured.

    :return: Instance of the Microsoft Sentinel class or None if not enabled/configured.
    """
    ms_sentinel_enabled = os.getenv("INPUT_MS_SENTINEL_ENABLED", "false").lower() == "true"
    if not ms_sentinel_enabled:
        # print("Microsoft Sentinel integration is disabled.")
        return None

    MS_SENTINEL_WORKSPACE_ID = os.getenv("INPUT_MS_SENTINEL_WORKSPACE_ID")
    MS_SENTINEL_SHARED_KEY = os.getenv("INPUT_MS_SENTINEL_SHARED_KEY")

    if not all([MS_SENTINEL_WORKSPACE_ID, MS_SENTINEL_SHARED_KEY]):
        print("Microsoft Sentinel environment variables are not properly configured!")
        return None

    return Sentinel(MS_SENTINEL_WORKSPACE_ID, MS_SENTINEL_SHARED_KEY)

def load_console_plugin():
    """
    Loads the Console plugin if it is enabled and properly configured.

    :return: Instance of the Console class or None if not enabled/configured.
    """
    console_enabled = os.getenv("INPUT_CONSOLE_ENABLED", "false").lower() == "true"
    if not console_enabled:
        print("Console Output integration is disabled.")
        return None

    SOCKET_CONSOLE_MODE = os.getenv("INPUT_SOCKET_CONSOLE_MODE", "console").lower()

    return Console(mode=SOCKET_CONSOLE_MODE)


def load_jira_plugin():
    """
    Loads the Jira plugin if it is enabled and properly configured.

    :return: Instance of the Jira class or None if not enabled/configured.
    """
    jira_enabled = os.getenv("INPUT_JIRA_ENABLED", "false").lower() == "true"
    if not jira_enabled:
        return None

    jira_url = os.getenv("INPUT_JIRA_URL")
    jira_email = os.getenv("INPUT_JIRA_EMAIL")
    jira_api_token = os.getenv("INPUT_JIRA_API_TOKEN")
    jira_project = os.getenv("INPUT_JIRA_PROJECT")

    if not all([jira_url, jira_email, jira_api_token, jira_project]):
        print("Jira environment variables are not properly configured!")
        return None

    config = {
        "enabled": True,
        "url": jira_url,
        "email": jira_email,
        "api_token": jira_api_token,
        "project": jira_project
    }

    return Jira(config)


def load_slack_plugin():
    """
    Loads the Slack plugin if it is enabled and properly configured.

    :return: Instance of the Slack class or None if not enabled/configured.
    """
    slack_enabled = os.getenv("INPUT_SLACK_ENABLED", "false").lower() == "true"
    if not slack_enabled:
        return None

    slack_webhook_url = os.getenv("INPUT_SLACK_WEBHOOK_URL")

    if not slack_webhook_url:
        print("Slack webhook URL is not properly configured!")
        return None

    return Slack(slack_webhook_url)


def load_teams_plugin():
    """
    Loads the Teams plugin if it is enabled and properly configured.

    :return: Instance of the Teams class or None if not enabled/configured.
    """
    teams_enabled = os.getenv("INPUT_TEAMS_ENABLED", "false").lower() == "true"
    if not teams_enabled:
        return None

    teams_webhook_url = os.getenv("INPUT_TEAMS_WEBHOOK_URL")

    if not teams_webhook_url:
        print("Teams webhook URL is not properly configured!")
        return None

    return Teams(teams_webhook_url)


def load_webhook_plugin():
    """
    Loads the Webhook plugin if it is enabled and properly configured.

    :return: Instance of the Webhook class or None if not enabled/configured.
    """
    webhook_enabled = os.getenv("INPUT_WEBHOOK_ENABLED", "false").lower() == "true"
    if not webhook_enabled:
        return None

    webhook_url = os.getenv("INPUT_WEBHOOK_URL")

    if not webhook_url:
        print("Webhook URL is not properly configured!")
        return None

    # Optional headers configuration
    headers = {"Content-Type": "application/json"}
    custom_headers = os.getenv("INPUT_WEBHOOK_HEADERS")
    if custom_headers:
        try:
            import json
            headers.update(json.loads(custom_headers))
        except json.JSONDecodeError:
            print("Warning: Failed to parse custom webhook headers, using defaults.")

    return Webhook(webhook_url, headers)