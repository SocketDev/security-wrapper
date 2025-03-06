from core.connectors.classes import TrivyDockerfileTestResult, TrivyImageTestResult
from core import BaseTool
from mdutils import MdUtils


class TrivyImage(BaseTool):
    result_class = TrivyImageTestResult
    default_severities = {"CRITICAL"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "Trivy Image") -> dict:
        """Processes Trivy Image results, extracting vulnerabilities."""
        metrics = {"tests": {}, "severities": {}, "output": [], "events": []}
        grouped_vulnerabilities = {}
        image_name = None
        for result in data.get("Results", []):
            vulnerabilities = result.get("Vulnerabilities", [])
            if not vulnerabilities:
                continue  # No vulnerabilities, so no events
            item_type = result.get("Type", "Unknown")
            item_class = result.get("Class", "Unknown")
            item_key = f"{item_class}_{item_type}"
            vuln_results = {}
            if item_key not in grouped_vulnerabilities:
                grouped_vulnerabilities[item_key] = {}
            for vuln in vulnerabilities:
                package = vuln.get("PkgID", "Unknown")
                severity = vuln.get("Severity", "UNKNOWN")
                title = vuln.get("Title", "")
                vuln_id = vuln.get("VulnerabilityID", "")
                cve_title = f"{vuln_id} - {title}"
                file = result.get("Target", "Unknown")
                url = vuln.get("PrimaryURL", "")
                if severity.lower() not in cls.default_severities:
                    continue
                if not image_name:
                    image_name = file
                if package not in vuln_results:
                    vuln_results[package] = {}
                if severity.lower() not in vuln_results[package]:
                    vuln_results[package][severity] = [
                        cve_title
                    ]
                else:
                    vuln_results[package][severity].append(cve_title)
            grouped_vulnerabilities[item_key].update(vuln_results)
        results = []
        for description in grouped_vulnerabilities:
            for package in grouped_vulnerabilities[description]:
                findings = grouped_vulnerabilities[description][package]
                if len(findings) == 0:
                    continue
                finding_results = ["<ul>"]
                for severity in findings:
                    for finding in findings[severity]:
                        finding_results.append(f"<li>**{severity}** - {finding}</li><br>")
                finding_results.append("</ul>")
                results.append((package, "".join(finding_results)))


        test_result = cls.result_class(
            Description=image_name
        )
        test_result.issue_text = TrivyImage.create_findings_table(results)
        test_result.use_custom = True
        test_result.has_first_line = True
        test_result.first_line = f"# Image: {image_name} Result<br>\n"
        test_result.plugin_name = plugin_name
        cls.extract_additional_data(test_result, cwd)
        metrics["events"].append(test_result)
        metrics["output"].append(test_result)
        return metrics

    @staticmethod
    def extract_additional_data(test_result, cwd):
        """Override in subclasses to extract tool-specific fields."""
        pass

    @staticmethod
    def get_test_name(test_result):
        return f"{test_result.plugin_name}_{test_result.file}"

    @staticmethod
    def create_findings_table(data: list[tuple[str, str]]) -> str:
        md = MdUtils(file_name="trivy_table.md")
        table_rows = [
            "Package",
            "Findings"
        ]
        number_of_columns = len(table_rows)
        for package, findings in data:
            table_rows.extend([package, findings.rstrip()])
        md.new_table(
            columns=number_of_columns,
            rows=len(table_rows) // number_of_columns,
            text=table_rows,
            text_align='left'
        )
        return md.file_data_text.lstrip()


class TrivyDockerfile(BaseTool):
    result_class = TrivyDockerfileTestResult
    default_severities = {"CRITICAL"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "Trivy Dockerfile") -> dict:
        """Processes Trivy Dockerfile results, extracting misconfigurations."""
        metrics = {"tests": {}, "severities": {}, "output": [], "events": []}

        for result in data.get("Results", []):
            for misconfig in result.get("Misconfigurations", []):
                test_result = cls.result_class(
                    Description=f"{misconfig['Type']} - {misconfig['ID']} - {misconfig['AVDID']}",
                    Title=misconfig.get("Title", ""),
                    Severity=misconfig.get("Severity", "UNKNOWN"),
                    File=result.get("Target", "Unknown"),
                    URL=misconfig.get("PrimaryURL", "")
                )
                if test_result.severity.lower() not in cls.default_severities:
                    continue
                test_result.issue_text = (
                    f"**Detection:** {test_result.description}\n"
                    f"**Title:** {test_result.title}\n"
                    f"**Severity:** {test_result.severity}\n"
                )
                test_result.plugin_name = plugin_name
                cls.extract_additional_data(test_result, cwd)
                metrics["events"].append(test_result)
                metrics["output"].append(test_result)

        return metrics

    @staticmethod
    def extract_additional_data(test_result, cwd):
        """Override in subclasses to extract tool-specific fields."""
        pass

    @staticmethod
    def get_test_name(test_result):
        return f"{test_result.plugin_name}_{test_result.file}"





