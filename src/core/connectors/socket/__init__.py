from core.connectors.classes import SocketReachabilityTestResult
from core import BaseTool
import json


class Socket(BaseTool):
    result_class = SocketReachabilityTestResult
    result_key = "components"
    default_severities = {"CRITICAL", "HIGH"}

    @classmethod
    def process_output(cls, data: dict, cwd: str, plugin_name: str = "SocketReachability") -> dict:
        """Processes Socket reachability scan output and ensures compatibility with create_output."""
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }

        components = data.get(cls.result_key, [])
        tier1_scan_id = data.get("tier1ReachabilityScanId", "")
        
        print(f"DEBUG: Processing {len(components)} components for Socket reachability")
        
        components_with_alerts = 0
        components_with_vulnerabilities = 0
        components_with_reachability = 0
        
        for component in components:
            # Skip empty components
            if not component:
                continue
                
            # Debug: Check what this component has
            has_vulnerabilities = bool(component.get("vulnerabilities"))
            has_reachability = bool(component.get("reachability"))
            
            if has_vulnerabilities:
                components_with_vulnerabilities += 1
            if has_reachability:
                components_with_reachability += 1
                
            # Create a test result for each component with reachability data
            test_result = cls.result_class(
                component=component,
                tier1_scan_id=tier1_scan_id,
                cwd=cwd,
                plugin_name=plugin_name
            )

            # Include components that have reachability alerts OR vulnerabilities
            if test_result.has_reachability_alerts() or has_vulnerabilities or has_reachability:
                components_with_alerts += 1
                test_name = cls.get_test_name(test_result)

                metrics["tests"].setdefault(test_name, 0)
                metrics["tests"][test_name] += 1

                metrics["output"].append(test_result)
                metrics["events"].append(test_result)

        print(f"DEBUG: Found {components_with_vulnerabilities} components with vulnerabilities")
        print(f"DEBUG: Found {components_with_reachability} components with reachability data")
        print(f"DEBUG: Including {components_with_alerts} components in results")

        return metrics

    @staticmethod
    def get_test_name(test_result):
        """Generate a test name based on the Socket reachability analysis."""
        component_name = getattr(test_result, 'name', 'unknown')
        severity = getattr(test_result, 'severity', 'unknown')
        return f"SocketReachability_{component_name}_{severity}"
