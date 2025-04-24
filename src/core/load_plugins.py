import os
from core.plugins.sumologic import Sumologic
from core.plugins.microsoft_sentinel import Sentinel
from core.plugins.console import Console


def load_sumo_logic_plugin():
    """
    Loads the Sumologic plugin if it is enabled and properly configured.

    :return: Instance of the Sumologic class or None if not enabled/configured.
    """
    sumo_logic_enabled = os.getenv("INPUT_SUMO_LOGIC_ENABLED", "false").lower() == "true"
    if not sumo_logic_enabled:
        print("Sumo Logic integration is disabled.")
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
        print("Microsoft Sentinel integration is disabled.")
        return None

    MS_SENTINEL_WORKSPACE_ID = os.getenv("INPUT_MS_SENTINEL_WORKSPACE_ID")
    MS_SENTINEL_SHARED_KEY = os.getenv("INPUT_MS_SENTINEL_SHARED_KEY")

    if not all([MS_SENTINEL_WORKSPACE_ID, MS_SENTINEL_SHARED_KEY]):
        print("Microsoft Sentinel environment variables are not properly configured!")
        return None

    return Sentinel(MS_SENTINEL_WORKSPACE_ID, MS_SENTINEL_SHARED_KEY)

def load_console_plugin():
    """
    Loads the Microsoft Sentinel plugin if it is enabled and properly configured.

    :return: Instance of the Microsoft Sentinel class or None if not enabled/configured.
    """
    console_enabled = os.getenv("INPUT_CONSOLE_ENABLED", "false").lower() == "true"
    if not console_enabled:
        print("Console Output integration is disabled.")
        return None

    SOCKET_CONSOLE_MODE = os.getenv("INPUT_SOCKET_CONSOLE_MODE", "console").lower()

    return Console(mode=SOCKET_CONSOLE_MODE)