"""
Socket Facts Processor

This module processes the consolidated .socket.facts.json file that contains both
Socket dependency data and external security tool results (SAST, secrets, container scans).
It extracts alerts and processes them using the existing tool connector classes.
"""

import json
import os
from typing import Dict, List, Any, Optional
from core.connectors.classes import BaseTestResult


class SocketFactsAlert(BaseTestResult):
    """Represents an alert from the consolidated socket facts."""
    
    def __init__(self, **kwargs):
        # Set default values
        self.alert_type = ""
        self.severity = ""
        self.generated_by = ""
        self.name = ""
        self.description = ""
        self.file = ""
        self.line = 1
        self.plugin_name = ""
        
        # Call parent constructor
        super().__init__(**kwargs)
        
        # Extract alert-specific fields from props if available
        props = kwargs.get('props', {})
        if props:
            for key, value in props.items():
                if not hasattr(self, key):  # Don't override existing attributes
                    setattr(self, key, value)
        
        # Extract location information
        location = kwargs.get('location', {})
        if location:
            self.file = location.get('file', self.file)
            self.line = location.get('start', self.line)
            self.line_number = self.line  # For compatibility
        
        # Set other fields from alert data
        self.alert_type = kwargs.get('type', self.alert_type)
        self.severity = kwargs.get('severity', self.severity) 
        self.generated_by = kwargs.get('generatedBy', self.generated_by)
        
        # Ensure we have required fields for compatibility
        if not hasattr(self, 'issue_severity'):
            self.issue_severity = self.severity.upper()
        if not hasattr(self, 'filename'):
            self.filename = self.file


class SocketFactsProcessor:
    """Processes consolidated socket facts file for security alerts."""
    
    def __init__(self):
        self.default_severities = {"CRITICAL"}
    
    def load_socket_facts(self, facts_file_path: str = ".socket.facts.json") -> Dict[str, Any]:
        """Load the consolidated socket facts file."""
        try:
            with open(facts_file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"components": []}
    
    def extract_alerts_by_type(self, facts_data: Dict[str, Any], alert_type_prefix: str) -> List[Dict[str, Any]]:
        """Extract all alerts of a specific type from socket facts."""
        alerts = []
        
        for component in facts_data.get("components", []):
            component_alerts = component.get("alerts", [])
            for alert in component_alerts:
                if alert.get("type", "").startswith(alert_type_prefix):
                    # Add component context to alert
                    alert_with_context = alert.copy()
                    alert_with_context["component"] = {
                        "id": component.get("id"),
                        "name": component.get("name"),
                        "type": component.get("type"),
                        "version": component.get("version")
                    }
                    alerts.append(alert_with_context)
        
        return alerts
    
    def process_sast_alerts(self, facts_data: Dict[str, Any], language: str, cwd: str, plugin_name: str) -> Dict[str, Any]:
        """Process SAST alerts for a specific language."""
        alert_type = f"external-sast-{language}"
        alerts = self.extract_alerts_by_type(facts_data, alert_type)
        
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }
        
        for alert_data in alerts:
            # Create alert object
            alert = SocketFactsAlert(
                cwd=cwd,
                **alert_data
            )
            alert.plugin_name = plugin_name
            
            # Filter by severity
            if alert.issue_severity.upper() not in self.default_severities:
                continue
            
            # Update metrics
            test_name = f"{plugin_name}_{alert.name}_{alert.severity}"
            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1
            
            metrics["output"].append(alert)
            metrics["events"].append(json.dumps(alert.__dict__))
        
        return metrics
    
    def process_secret_alerts(self, facts_data: Dict[str, Any], cwd: str, plugin_name: str) -> Dict[str, Any]:
        """Process secret scanning alerts."""
        alerts = self.extract_alerts_by_type(facts_data, "external-secrets")
        
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }
        
        for alert_data in alerts:
            # Create alert object
            alert = SocketFactsAlert(
                cwd=cwd,
                **alert_data
            )
            alert.plugin_name = plugin_name
            
            # Filter by severity
            if alert.issue_severity.upper() not in self.default_severities:
                continue
            
            # Update metrics
            test_name = f"{plugin_name}_{alert.name}_{alert.severity}"
            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1
            
            metrics["output"].append(alert)
            metrics["events"].append(json.dumps(alert.__dict__))
        
        return metrics
    
    def process_container_alerts(self, facts_data: Dict[str, Any], scan_type: str, cwd: str, plugin_name: str) -> Dict[str, Any]:
        """Process container/dockerfile scanning alerts."""
        alert_type = f"external-container-{scan_type}"
        alerts = self.extract_alerts_by_type(facts_data, alert_type)
        
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }
        
        for alert_data in alerts:
            # Create alert object
            alert = SocketFactsAlert(
                cwd=cwd,
                **alert_data
            )
            alert.plugin_name = plugin_name
            
            # Filter by severity
            if alert.issue_severity.upper() not in self.default_severities:
                continue
            
            # Update metrics
            test_name = f"{plugin_name}_{alert.name}_{alert.severity}"
            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1
            
            metrics["output"].append(alert)
            metrics["events"].append(json.dumps(alert.__dict__))
        
        return metrics
    
    def process_socket_sca_alerts(self, facts_data: Dict[str, Any], cwd: str, plugin_name: str) -> Dict[str, Any]:
        """Process Socket SCA alerts."""
        alerts = self.extract_alerts_by_type(facts_data, "external-socket-sca")
        
        metrics = {
            "tests": {},
            "severities": {},
            "output": [],
            "events": []
        }
        
        # Check for scan failures
        scan_failed = False
        for alert_data in alerts:
            if alert_data.get("props", {}).get("scan_failed", False):
                scan_failed = True
                break
        
        if scan_failed:
            return {"scan_failed": True, "tests": {}, "severities": {}, "output": [], "events": []}
        
        for alert_data in alerts:
            # Create alert object
            alert = SocketFactsAlert(
                cwd=cwd,
                **alert_data
            )
            alert.plugin_name = plugin_name
            
            # Filter by severity
            if alert.issue_severity.upper() not in self.default_severities:
                continue
            
            # Update metrics
            test_name = f"{plugin_name}_{alert.name}_{alert.severity}"
            metrics["tests"].setdefault(test_name, 0)
            metrics["tests"][test_name] += 1
            
            metrics["output"].append(alert)
            metrics["events"].append(json.dumps(alert.__dict__))
        
        return metrics
