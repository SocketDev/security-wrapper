import json
from mdutils import MdUtils
from typing import Union
import logging
import inspect

log = logging.getLogger("socket-external-tool")
log.addHandler(logging.NullHandler())

__all__ = [
    "marker",
    "__version__",
    "__author__",
    "log",
    "base_github"
]

__version__ = "1.0.12"
__author__ = "socket.dev"
base_github = "https://github.com"

marker = f"<!--Socket External Tool Runner: REPLACE_ME -->"


class BaseTool:
    result_class = None  # Must be set in subclasses
    result_key = "results"  # Default key for test results, overridden as needed

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "") -> dict:
        results = data.get(cls.result_key, [])
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }

        for test in results:
            test_result = cls.result_class(**test, cwd=cwd)
            test_result.plugin_name = plugin_name

            cls.extract_additional_data(test_result, cwd)

            test_name = cls.get_test_name(test_result)

            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1

            if hasattr(test_result, "severity"):
                metrics["severities"].setdefault(test_result.severity, 0)
                metrics["severities"][test_result.severity] += 1

            metrics["output"].append(test_result)
            metrics["events"].append(json.dumps(test_result.__dict__))

        return metrics

    @staticmethod
    def extract_additional_data(test_result, cwd):
        """Override in subclasses to extract tool-specific fields."""
        pass

    @staticmethod
    def get_test_name(test_result):
        """Override in subclasses to define test name structure."""
        return "test_result"

    @classmethod
    def create_output(cls, data: dict, marker: str, repo: str, commit: str, cwd: str, show_unverified=None) -> (
    Union[str, None], dict):
        """Formats output as properly structured Markdown."""

        # Determine if the connector supports the show_verified argument
        supports_show_verified = "show_unverified" in inspect.signature(cls.process_output).parameters

        # Conditionally call process_output with show_verified if the connector supports it
        if supports_show_verified:
            show_unverified_param = show_unverified if show_unverified is not None else False
            result = cls.process_output(data, cwd=cwd, show_unverified=show_unverified_param)
        else:
            result = cls.process_output(data, cwd=cwd)  # Call without show_verified

        md = MdUtils(file_name=f"{cls.__name__.lower()}_comments.md")
        output_str = ""

        if len(result["output"]) > 0:
            md.new_line(marker)
            # md.new_line("<br>")
            md.new_line()

            set_first_line = False
            for output in result["output"]:
                file_link = (
                    f"[{output.file}]({output.url.replace('REPO_REPLACE', repo).replace('COMMIT_REPLACE', commit)})"
                    if hasattr(output, "url") else f"`{output.file}`"
                )
                has_first_line = output.__dict__.get("has_first_line", False)
                if has_first_line and not set_first_line:
                    md.new_line(output.__dict__.get("first_line", ""))
                    set_first_line = True
                use_custom = output.__dict__.get("use_custom", False)
                if not use_custom:
                    md.new_line(f"**{output.__dict__.get('issue_text', 'Detection')}**")
                    md.new_line(f"**Severity**: `{output.__dict__.get('severity', 'N/A')}`")
                    md.new_line(f"**Filename:** {file_link}")
                else:
                    source = output.__dict__.get('issue_text', '').replace('REPLACE_FILE_LINK', file_link)
                    issue_text = f"{source.replace('REPO_REPLACE', repo).replace('COMMIT_REPLACE', commit)}"
                    md.new_line(issue_text)

                if hasattr(output, "code"):
                    language = "python" if "Bandit" in cls.__name__ else "go" if "Gosec" in cls.__name__ else ""
                    md.insert_code(output.code, language=language)

                # md.new_line("<br>")
                md.new_line()

            md.create_md_file()
            output_str = md.file_data_text.lstrip()

        return result, output_str

