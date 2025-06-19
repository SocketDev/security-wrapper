import json
import logging
import os
import glob
import inspect
from core import marker
from core.connectors.bandit import Bandit
from core.connectors.gosec import Gosec
from core.connectors.trufflehog import Trufflehog
from core.connectors.trivy import TrivyImage, TrivyDockerfile
from core.connectors.eslint import ESLint
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
SEVERITIES= os.getenv("INPUT_FINDING_SEVERITIES")
if SEVERITIES is not None:
    SEVERITIES = set(SEVERITIES.split(","))
if not GIT_DIR and SCM_DISABLED:
    print("GIT_DIR is not set and is required if SCM_DISABLED=true")
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

# Define tool names
TOOL_CLASSES = {
    "bandit": Bandit,
    "gosec": Gosec,
    "trufflehog": Trufflehog,
    "trivy_image": TrivyImage,
    "trivy_dockerfile": TrivyDockerfile,
    "eslint": ESLint
}

TOOL_NAMES = {
    "bandit": "Bandit",
    "gosec": "Gosec",
    "trufflehog": "Trufflehog",
    "trivy_image": "TrivyImageScanning",
    "trivy_dockerfile": "TrivyDockerfileScanning",
    "eslint": "ESLint"
}

def main():
    # Load results
    results = {
        "bandit": load_json("bandit_output.json", "Bandit"),
        "gosec": load_json("gosec_output.json", "Gosec"),
        "trufflehog": load_json("trufflehog_output.json", "Trufflehog"),
        "trivy_image": consolidate_trivy_results("trivy_image_*.json"),
        "trivy_dockerfile": consolidate_trivy_results("trivy_dockerfile_*.json"),
        "eslint": load_json("eslint_output.json", "ESLint")
    }

    if any(results.values()):
        if not SCM_DISABLED:
            scm = SCM() # type: ignore
            tool_outputs = {}
            tool_events = {}

            for key, data in results.items():
                if data:
                    tool_marker = marker.replace("REPLACE_ME", TOOL_NAMES[key])
                    tool_class = TOOL_CLASSES[key]
                    if SEVERITIES:
                        tool_class.default_severities = SEVERITIES

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
            for key, data in results.items():
                if key not in TOOL_CLASSES or not data:
                    continue
                TOOL_CLASSES[key].default_severities = SEVERITIES
                tool_events[key] = TOOL_CLASSES[key].process_output(data, GIT_DIR, TOOL_NAMES[key])

        if len(tool_events) > 0:
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
        exit(1)
    else:
        print("No issues detected with Socket Security Tools")

if __name__ == "__main__":
    main()
