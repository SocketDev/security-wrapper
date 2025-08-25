import json
import logging
import os
import glob
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
from core.load_plugins import load_sumo_logic_plugin, load_ms_sentinel_plugin, load_console_plugin
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


def load_json(filename, connector: str) -> dict:
    """Loads JSON or NDJSON files, handling Trufflehog's NDJSON format."""
    try:
        with open(filename, 'r') as file:
            if connector.lower() == "trufflehog":
                return {"Issues": [json.loads(line) for line in file]}
            else:
                return json.load(file)
    except json.JSONDecodeError:
        print(f"No results found for {connector}")
        return {}
    except FileNotFoundError:
        print(f"No results found for {connector}")
        return {}

def consolidate_trivy_results(pattern: str) -> dict:
    """Consolidates multiple Trivy result JSONs into a single structure."""
    consolidated_results = {"Results": []}
    for filename in glob.glob(pattern):
        data = load_json(filename, "Trivy")
        if "Results" in data:
            consolidated_results["Results"].extend(data["Results"])
    return consolidated_results

sumo_client = load_sumo_logic_plugin()
ms_sentinel = load_ms_sentinel_plugin()
console_output = load_console_plugin()

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
    
    def get_output_file_path(filename):
        """Get the full path to an output file based on TEMP_OUTPUT_DIR"""
        return os.path.join(temp_output_dir, filename)
    
    # Check if we have a consolidated .socket.facts.json file
    socket_facts_path = ".socket.facts.json"
    if os.path.exists(socket_facts_path):
        print("Using consolidated .socket.facts.json format")
        
        # Initialize facts processor
        facts_processor = SocketFactsProcessor()
        facts_processor.default_severities = SEVERITIES
        facts_data = facts_processor.load_socket_facts(socket_facts_path)
        
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
        
    else:
        print("Using legacy individual tool output format")
        # Fallback to legacy processing if no consolidated facts file
        results = {}
        if "bandit" in TOOL_CLASSES:
            bandit_data = load_json(get_output_file_path("bandit_output.json"), "Bandit")
            if bandit_data:
                results["bandit"] = bandit_data
        if "gosec" in TOOL_CLASSES:
            gosec_data = load_json(get_output_file_path("gosec_output.json"), "Gosec")
            if gosec_data:
                results["gosec"] = gosec_data
        if "trufflehog" in TOOL_CLASSES:
            trufflehog_data = load_json(get_output_file_path("trufflehog_output.json"), "Trufflehog")
            if trufflehog_data:
                results["trufflehog"] = trufflehog_data
        if "trivy_image" in TOOL_CLASSES:
            trivy_image_data = consolidate_trivy_results(get_output_file_path("trivy_image_*.json"))
            if trivy_image_data and trivy_image_data.get("Results"):
                results["trivy_image"] = trivy_image_data
        if "trivy_dockerfile" in TOOL_CLASSES:
            trivy_dockerfile_data = consolidate_trivy_results(get_output_file_path("trivy_dockerfile_*.json"))
            if trivy_dockerfile_data and trivy_dockerfile_data.get("Results"):
                results["trivy_dockerfile"] = trivy_dockerfile_data
        if "eslint" in TOOL_CLASSES:
            eslint_data = load_json(get_output_file_path("eslint_output.json"), "ESLint")
            if eslint_data:
                results["eslint"] = eslint_data
        if "socket" in TOOL_CLASSES:
            socket_data = load_json(".socket.facts.json", "Socket")
            if socket_data:
                results["socket"] = socket_data
        if "socket_sca" in TOOL_CLASSES:
            socket_sca_data = load_json(get_output_file_path("socket_sca_output.json"), "SocketSCA")
            if socket_sca_data:
                results["socket_sca"] = socket_sca_data

    if any(results.values()):
        if not SCM_DISABLED:
            scm = SCM() # type: ignore
            tool_outputs = {}
            tool_events = {}
            for key, data in results.items():
                if data:
                    tool_marker = marker.replace("REPLACE_ME", TOOL_NAMES[key])
                    tool_class = TOOL_CLASSES[key]
                    tool_class.default_severities = SEVERITIES
                    
                    # Handle consolidated facts vs legacy data differently
                    if key == "socket" and "components" in data:
                        # For socket dependency data, use the original create_output method
                        supports_show_unverified = "show_unverified" in inspect.signature(tool_class.process_output).parameters
                        if supports_show_unverified:
                            show_unverified = os.getenv("INPUT_TRUFFLEHOG_SHOW_UNVERIFIED", "false").lower() == "true"
                            tool_outputs[key], tool_results = tool_class.create_output(
                                data,
                                tool_marker,
                                scm.github.repo,
                                scm.github.commit,
                                scm.github.cwd,
                                show_unverified=show_unverified
                            )
                        else:
                            tool_outputs[key], tool_results = tool_class.create_output(
                                data, tool_marker, scm.github.repo, scm.github.commit, scm.github.cwd
                            )
                    elif isinstance(data, dict) and "output" in data:
                        # For consolidated security tool data, create output from processed alerts
                        tool_outputs[key] = {
                            "events": data.get("output", []),
                            "output": [str(alert) for alert in data.get("output", [])]
                        }
                        tool_results = "\n".join(tool_outputs[key]["output"])
                    else:
                        # Legacy processing for individual tool outputs
                        supports_show_unverified = "show_unverified" in inspect.signature(tool_class.process_output).parameters
                        if supports_show_unverified:
                            show_unverified = os.getenv("INPUT_TRUFFLEHOG_SHOW_UNVERIFIED", "false").lower() == "true"
                            tool_outputs[key], tool_results = tool_class.create_output(
                                data,
                                tool_marker,
                                scm.github.repo,
                                scm.github.commit,
                                scm.github.cwd,
                                show_unverified=show_unverified
                            )
                        else:
                            tool_outputs[key], tool_results = tool_class.create_output(
                                data, tool_marker, scm.github.repo, scm.github.commit, scm.github.cwd
                            )
                    
                    tool_events[key] = tool_outputs[key].get("events", [])
                    if tool_events[key]:
                        scm.github.post_comment(TOOL_NAMES[key], tool_marker, tool_results)
            print("Issues detected with Security Tools. Please check PR comments")
        else:
            tool_events = {}
            cwd = GIT_DIR if GIT_DIR else os.getcwd()
            for key, data in results.items():
                if key not in TOOL_CLASSES or not data:
                    continue
                TOOL_CLASSES[key].default_severities = SEVERITIES
                
                # Handle consolidated facts vs legacy data differently
                if isinstance(data, dict) and "output" in data:
                    # For consolidated security tool data, we already have processed events
                    tool_events[key] = {"events": data.get("output", [])}
                else:
                    # Legacy processing for individual tool outputs
                    tool_events[key] = TOOL_CLASSES[key].process_output(data, cwd, TOOL_NAMES[key])

        # Check for scan failures that should force an exit regardless of other conditions
        scan_failed = False
        for key, data in results.items():
            if isinstance(data, dict) and data.get("scan_failed", False):
                print(f"{TOOL_NAMES.get(key, key)} scan failed")
                scan_failed = True

        if len(tool_events) > 0 or scan_failed:
            # Only show integration messages if there is at least one event
            total_events = sum(len(events.get("events", [])) for events in tool_events.values())
            if total_events > 0:
                if sumo_client:
                    print("Issues detected with Security Tools. Please check Sumologic Events")
                if ms_sentinel:
                    print("Issues detected with Security Tools. Please check Microsoft Sentinel Events")
                if console_output:
                    print("Issues detected with Security Tools.")

        for key, events in tool_events.items():
            tool_name = f"SocketSecurityTools-{TOOL_NAMES[key]}"
            formatted_events = [json.dumps(event, default=lambda o: o.to_json()) for event in
                                events.get("events", [])]
            if sumo_client:
                print(errors) if (errors := sumo_client.send_events(formatted_events, tool_name)) else []

            if ms_sentinel:
                print(errors) if (errors := ms_sentinel.send_events(formatted_events, tool_name)) else []

            if console_output:
                print(errors) if (errors := console_output.print_events(events.get("output", []), key)) else []
        
        if scan_failed:
            print("Security scan failed - exiting with error")
        exit(1)
    else:
        print("No issues detected with Socket Security Tools")

if __name__ == "__main__":
    main()
