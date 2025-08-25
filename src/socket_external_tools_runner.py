import json
import logging
import os
import inspect
from version import __version__
from core import marker
from core.connectors.bandit import Bandit
from core.connectors.gosec import Gosec
from core.connectors.trufflehog import Trufflehog
from core.connectors.trivy import TrivyImage, TrivyDockerfile
from core.connectors.eslint import ESLint
from core.connectors.socket import Socket
from core.connectors.socket_sca import SocketSCA
from core.socket_facts_processor import SocketFactsProcessor
from core.socket_facts_consolidator import SocketFactsConsolidator
from core.load_plugins import (
    load_sumo_logic_plugin, 
    load_ms_sentinel_plugin, 
    load_console_plugin,
    load_jira_plugin,
    load_slack_plugin,
    load_teams_plugin,
    load_webhook_plugin
)
from tabulate import tabulate

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("socket-security-wrapper")

SCM_DISABLED = os.getenv("SOCKET_SCM_DISABLED", "false").lower() == "true"
if not SCM_DISABLED:
    from core.scm import SCM
else:
    SCM = None
GIT_DIR = os.getenv("GITHUB_REPOSITORY", None)
SEVERITIES = os.getenv("INPUT_FINDING_SEVERITIES")
if SEVERITIES is not None:
    SEVERITIES = set(SEVERITIES.split(","))
else:
    SEVERITIES = {"CRITICAL"}
if not GIT_DIR and not SCM_DISABLED:
    print("GIT_DIR is not set and is required unless SCM_DISABLED=true")
    exit(1)

def print_tool_events_summary(tool_events):
    """
    Prints a summary of tool event results in a tabular format.
    """
    output_file_name = os.getenv("OUTPUT_FILE_NAME", "security_tools_summary.json")
    summary = []
    if not tool_events:
        print("\nNo issues were detected by any tools.")
        return

    for tool_name, events in tool_events.items():
        summary.append({
            "Tool": tool_name.capitalize(),
            "Issues Detected": len(events.get("events", [])),
            "Details": f"See {tool_name}_output.json"  # Reference output file
        })

    print("\nSecurity Tools Summary:\n")
    print(tabulate(summary, headers="keys", tablefmt="fancy_grid"))


def print_tool_events_summary(tool_events):
    """
    Prints a summary of tool event results in a tabular format.
    """
    output_file_name = os.getenv("OUTPUT_FILE_NAME", "security_tools_summary.json")
    summary = []
    if not tool_events:
        print("\nNo issues were detected by any tools.")
        return

    for tool_name, events in tool_events.items():
        summary.append({
            "Tool": tool_name.capitalize(),
            "Issues Detected": len(events.get("events", [])),
            "Details": f"See {tool_name}_output.json"  # Reference output file
        })

    print("\nSecurity Tools Summary:\n")
    print(tabulate(summary, headers="keys", tablefmt="fancy_grid"))


sumo_client = load_sumo_logic_plugin()
ms_sentinel = load_ms_sentinel_plugin()
console_output = load_console_plugin()
jira_client = load_jira_plugin()
slack_client = load_slack_plugin()
teams_client = load_teams_plugin()
webhook_client = load_webhook_plugin()

# Dynamically build tool classes and names based on enabled inputs
TOOL_CLASSES = {}
TOOL_NAMES = {}
if os.getenv("INPUT_PYTHON_SAST_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["bandit"] = Bandit
    TOOL_NAMES["bandit"] = "Bandit"
if os.getenv("INPUT_GOLANG_SAST_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["gosec"] = Gosec
    TOOL_NAMES["gosec"] = "Gosec"
if os.getenv("INPUT_SECRET_SCANNING_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["trufflehog"] = Trufflehog
    TOOL_NAMES["trufflehog"] = "Trufflehog"
if os.getenv("INPUT_TRIVY_IMAGE_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["trivy_image"] = TrivyImage
    TOOL_NAMES["trivy_image"] = "TrivyImageScanning"
if os.getenv("INPUT_TRIVY_DOCKERFILE_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["trivy_dockerfile"] = TrivyDockerfile
    TOOL_NAMES["trivy_dockerfile"] = "TrivyDockerfileScanning"
if os.getenv("INPUT_JAVASCRIPT_SAST_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["eslint"] = ESLint
    TOOL_NAMES["eslint"] = "ESLint"
if os.getenv("INPUT_SOCKET_SCANNING_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["socket"] = Socket
    TOOL_NAMES["socket"] = "SocketReachability"
if os.getenv("INPUT_SOCKET_SCA_ENABLED", "false").lower() == "true":
    TOOL_CLASSES["socket_sca"] = SocketSCA
    TOOL_NAMES["socket_sca"] = "SocketSCA"

def main():
    # Get the output directory for temp files
    temp_output_dir = os.getenv("TEMP_OUTPUT_DIR", ".")
    
    # Check if we have a consolidated .socket.facts.json file
    socket_facts_path = ".socket.facts.json"
    if os.path.exists(socket_facts_path):
        print("Using consolidated .socket.facts.json format")
        
        # Initialize facts processor for processing alerts
        facts_processor = SocketFactsProcessor()
        facts_processor.default_severities = SEVERITIES
        
        # Load the facts data (consolidator already handled S3 download/upload and new alert detection)
        facts_data = facts_processor.load_socket_facts(socket_facts_path)
        
        # Ensure new_alerts field exists (fallback if consolidator didn't set it)
        if "new_alerts" not in facts_data:
            all_alerts = []
            for component in facts_data.get("components", []):
                all_alerts.extend(component.get("alerts", []))
            facts_data["new_alerts"] = all_alerts
            facts_data["new_alerts_count"] = len(all_alerts)
            print(f"DEBUG: new_alerts not found in facts data, treating all {len(all_alerts)} alerts as new")
        
        # Process results from consolidated facts
        results = {}
        
        # Process Socket dependency data (original socket facts)
        socket_components = [c for c in facts_data.get("components", []) if c.get("type") in ["npm", "pypi", "go", "maven", "nuget"]]
        if socket_components:
            # Create a socket facts data structure with only dependency components
            socket_data = {"components": socket_components}
            if socket_data:
                results["socket"] = socket_data
        
        # Process external security tool alerts from facts
        if "bandit" in TOOL_CLASSES:
            bandit_metrics = facts_processor.process_sast_alerts(facts_data, "python", os.getcwd(), "Bandit")
            if bandit_metrics.get("output"):
                results["bandit"] = bandit_metrics
        
        if "gosec" in TOOL_CLASSES:
            gosec_metrics = facts_processor.process_sast_alerts(facts_data, "golang", os.getcwd(), "Gosec")
            if gosec_metrics.get("output"):
                results["gosec"] = gosec_metrics
        
        if "eslint" in TOOL_CLASSES:
            eslint_metrics = facts_processor.process_sast_alerts(facts_data, "javascript", os.getcwd(), "ESLint")
            if eslint_metrics.get("output"):
                results["eslint"] = eslint_metrics
        
        if "trufflehog" in TOOL_CLASSES:
            trufflehog_metrics = facts_processor.process_secret_alerts(facts_data, os.getcwd(), "Trufflehog")
            if trufflehog_metrics.get("output"):
                results["trufflehog"] = trufflehog_metrics
        
        if "trivy_image" in TOOL_CLASSES:
            trivy_image_metrics = facts_processor.process_container_alerts(facts_data, "image", os.getcwd(), "TrivyImageScanning")
            if trivy_image_metrics.get("output"):
                results["trivy_image"] = trivy_image_metrics
        
        if "trivy_dockerfile" in TOOL_CLASSES:
            trivy_dockerfile_metrics = facts_processor.process_container_alerts(facts_data, "dockerfile", os.getcwd(), "TrivyDockerfileScanning")
            if trivy_dockerfile_metrics.get("output"):
                results["trivy_dockerfile"] = trivy_dockerfile_metrics
        
        if "socket_sca" in TOOL_CLASSES:
            socket_sca_metrics = facts_processor.process_socket_sca_alerts(facts_data, os.getcwd(), "SocketSCA")
            if socket_sca_metrics.get("output") or socket_sca_metrics.get("scan_failed"):
                results["socket_sca"] = socket_sca_metrics
        
        # Process consolidated facts for Jira integration
        print(f"DEBUG: About to check Jira client: {jira_client is not None}")
        if jira_client:
            # Check if there are any new security alerts in the facts data
            new_alerts = facts_data.get("new_alerts", [])
            total_alerts = len(new_alerts)
            print(f"DEBUG: New alerts found: {total_alerts}")
            if total_alerts > 0:
                print("Processing new security alerts for Jira integration.")
                print("DEBUG: Calling jira_client.send_consolidated_security_alerts()")
                jira_result = jira_client.send_consolidated_security_alerts(facts_data)
                print(f"DEBUG: Jira result: {jira_result}")
                if jira_result.get("status") == "error":
                    print(f"Jira error: {jira_result.get('message', 'Unknown error')}")
                elif jira_result.get("status") == "success":
                    if jira_result.get("created"):
                        print(f"Created new Jira ticket: {jira_result.get('issue_key')}")
                    elif jira_result.get("comment_added"):
                        print(f"Added new alerts to existing Jira ticket: {jira_result.get('issue_key')}")
                    else:
                        print(f"Jira ticket up to date: {jira_result.get('issue_key', 'No new alerts')}")
            else:
                print("DEBUG: No new alerts found, skipping Jira integration")
        else:
            print("DEBUG: Jira client is None, skipping Jira integration")
        
        # Process consolidated facts for Slack integration
        print(f"DEBUG: About to check Slack client: {slack_client is not None}")
        if slack_client:
            new_alerts = facts_data.get("new_alerts", [])
            total_alerts = len(new_alerts)
            if total_alerts > 0:
                print("Processing new security alerts for Slack integration.")
                slack_result = slack_client.send_consolidated_security_alerts(facts_data)
                print(f"DEBUG: Slack result: {slack_result}")
                if slack_result.get("status") == "error":
                    print(f"Slack error: {slack_result.get('message', 'Unknown error')}")
                elif slack_result.get("status") == "success":
                    print("Successfully sent alerts to Slack")
            else:
                print("DEBUG: No new alerts found, skipping Slack integration")
        else:
            print("DEBUG: Slack client is None, skipping Slack integration")
        
        # Process consolidated facts for Teams integration
        print(f"DEBUG: About to check Teams client: {teams_client is not None}")
        if teams_client:
            new_alerts = facts_data.get("new_alerts", [])
            total_alerts = len(new_alerts)
            if total_alerts > 0:
                print("Processing new security alerts for Teams integration.")
                teams_result = teams_client.send_consolidated_security_alerts(facts_data)
                print(f"DEBUG: Teams result: {teams_result}")
                if teams_result.get("status") == "error":
                    print(f"Teams error: {teams_result.get('message', 'Unknown error')}")
                elif teams_result.get("status") == "success":
                    print("Successfully sent alerts to Teams")
            else:
                print("DEBUG: No new alerts found, skipping Teams integration")
        else:
            print("DEBUG: Teams client is None, skipping Teams integration")
        
        # Process consolidated facts for Webhook integration
        print(f"DEBUG: About to check Webhook client: {webhook_client is not None}")
        if webhook_client:
            new_alerts = facts_data.get("new_alerts", [])
            total_alerts = len(new_alerts)
            if total_alerts > 0:
                print("Processing new security alerts for Webhook integration.")
                webhook_result = webhook_client.send_consolidated_security_alerts(facts_data)
                print(f"DEBUG: Webhook result: {webhook_result}")
                if webhook_result.get("status") == "error":
                    print(f"Webhook error: {webhook_result.get('message', 'Unknown error')}")
                elif webhook_result.get("status") == "success":
                    print("Successfully sent alerts via Webhook")
            else:
                print("DEBUG: No new alerts found, skipping Webhook integration")
        else:
            print("DEBUG: Webhook client is None, skipping Webhook integration")
        
        # Note: S3 upload was already handled by the consolidator in entrypoint.sh
        
        # Check for scan failures that should force an exit regardless of other conditions
        scan_failed = False
        for key, data in results.items():
            if isinstance(data, dict) and data.get("scan_failed", False):
                print(f"{TOOL_NAMES.get(key, key)} scan failed")
                scan_failed = True

        if scan_failed:
            print("Security scan failed - exiting with error")
            exit(1)
        
        # Check if there are any new security alerts to report
        new_alerts_count = facts_data.get("new_alerts_count", 0)
        if new_alerts_count > 0:
            print(f"Security issues detected - {new_alerts_count} new alerts found - check consolidated integrations (Jira, Slack, Teams, Webhook)")
            exit(1)
        else:
            print("No new security issues detected with Socket Security Tools")
        
    else:
        print("No consolidated .socket.facts.json file found - exiting")
        return

if __name__ == "__main__":
    main()
