import json
import logging
import os
import glob
import inspect
from core import marker
from core.scm import SCM
from core.connectors.bandit import Bandit
from core.connectors.gosec import Gosec
from core.connectors.trufflehog import Trufflehog
from core.connectors.trivy import TrivyImage, TrivyDockerfile
from core.connectors.eslint import ESLint
from core.load_plugins import load_sumo_logic_plugin, load_ms_sentinel_plugin

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("example")

SCM_DISABLED = os.getenv("SOCKET_SCM_DISABLED", "false").lower() == "true"
GIT_DIR = os.getenv("GITHUB_REPOSITORY", None)
SEVERITIES= os.getenv("INPUT_FINDING_SEVERITIES")
if SEVERITIES is not None:
    SEVERITIES = set(SEVERITIES.split(","))
if not GIT_DIR and SCM_DISABLED:
    print("GIT_DIR is not set and is required if SCM_DISABLED=true")
    exit(1)

def load_json(filename, connector: str) -> dict:
    """Loads JSON or NDJSON files, handling Trufflehog's NDJSON format."""
    try:
        with open(filename, 'r') as file:
            if connector.lower() == "trufflehog":
                return {"Issues": [json.loads(line) for line in file]}
            else:
                return json.load(file)
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
        scm = SCM()
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
        tool_events = {
            key: TOOL_CLASSES[key].process_output(data, GIT_DIR, TOOL_NAMES[key])
            for key, data in results.items() if data
        }

    if sumo_client:
        print("Issues detected with Security Tools. Please check Sumologic Events")
        for key, events in tool_events.items():
            print(errors) if (errors := sumo_client.send_events(events.get("events"), "../" + key + "_output.json")) else []

    if ms_sentinel:
        print("Issues detected with Security Tools. Please check Microsoft Sentinel Events")
        for key, events in tool_events.items():
            sentinel_name = f"SocketSecurityTools{TOOL_NAMES[key]}"
            formatted_events = [json.dumps(event) for event in events.get("events", [])]
            print(errors) if (errors := ms_sentinel.send_events(formatted_events, sentinel_name)) else []
    exit(1)
else:
    print("No issues detected with Socket Security Tools")
