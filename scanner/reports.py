"""
Report Generation Module

Generates findings from vulnerability scans in multiple formats.

Phase 1: JSON and text report formats
Phase 2: HTML, PDF, SARIF formats + database persistence
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from .vulnerability_scanner import Vulnerability, VulnerabilityScanner, SeverityLevel


logger = logging.getLogger(__name__)


class ScanReport:
    """Represents a complete scan report."""
    
    def __init__(
        self,
        scan_id: str,
        input_text: str,
        vulnerabilities: List[Vulnerability],
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize scan report.
        
        Args:
            scan_id: Unique scan identifier
            input_text: Text that was scanned
            vulnerabilities: List of detected vulnerabilities
            context: Optional context information
            metadata: Optional additional metadata
        """
        self.scan_id = scan_id
        self.input_text = input_text
        self.vulnerabilities = vulnerabilities
        self.context = context
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.INFO.value: 0,
        }
        
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        
        return counts
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts = {}
        for vuln in self.vulnerabilities:
            type_name = vuln.type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts
    
    def summary(self) -> Dict[str, Any]:
        """Generate report summary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": self._count_by_severity(),
            "type_breakdown": self._count_by_type(),
            "highest_severity": self._get_highest_severity(),
            "context": self.context,
        }
    
    def _get_highest_severity(self) -> Optional[str]:
        """Get the highest severity level found."""
        if not self.vulnerabilities:
            return None
        
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]
        
        for severity in severity_order:
            if any(v.severity == severity for v in self.vulnerabilities):
                return severity.value
        
        return None
    
    def to_json(self, include_input: bool = False) -> str:
        """
        Convert report to JSON.
        
        Args:
            include_input: Whether to include the original input text
            
        Returns:
            JSON string
        """
        data = {
            "report": self.summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
        
        if include_input:
            data["input_text"] = self.input_text
        
        if self.metadata:
            data["metadata"] = self.metadata
        
        return json.dumps(data, indent=2)
    
    def to_dict(self, include_input: bool = False) -> Dict[str, Any]:
        """Convert report to dictionary."""
        data = {
            "report": self.summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
        
        if include_input:
            data["input_text"] = self.input_text
        
        if self.metadata:
            data["metadata"] = self.metadata
        
        return data
    
    def to_text(self) -> str:
        """Convert report to human-readable text format."""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        summary = self.summary()
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Scan ID: {summary['scan_id']}")
        lines.append(f"Timestamp: {summary['timestamp']}")
        lines.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        lines.append(f"Highest Severity: {summary['highest_severity'] or 'None'}")
        
        if summary["context"]:
            lines.append(f"Context: {summary['context']}")
        
        lines.append("")
        
        # Severity breakdown
        lines.append("SEVERITY BREAKDOWN")
        lines.append("-" * 40)
        for severity, count in summary["severity_breakdown"].items():
            lines.append(f"  {severity.upper()}: {count}")
        
        lines.append("")
        
        # Vulnerabilities
        if self.vulnerabilities:
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                lines.append(f"\n[{i}] {vuln.type.value.upper()}")
                lines.append(f"    Severity: {vuln.severity.value}")
                lines.append(f"    Confidence: {vuln.confidence:.1%}")
                lines.append(f"    Description: {vuln.description}")
                
                if vuln.location:
                    lines.append(f"    Location: {vuln.location}")
                
                if vuln.payload:
                    payload_preview = vuln.payload[:50] + "..." if len(vuln.payload) > 50 else vuln.payload
                    lines.append(f"    Payload: {payload_preview}")
                
                if vuln.remediation:
                    lines.append(f"    Remediation: {vuln.remediation}")
        else:
            lines.append("RESULT: No vulnerabilities detected ✓")
        
        lines.append("")
        lines.append("=" * 80)
        
        return "\n".join(lines)


class ReportGenerator:
    """Generates reports from scan results."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for saving reports (optional)
        """
        self.output_dir = Path(output_dir) if output_dir else Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"ReportGenerator initialized with output dir: {self.output_dir}")
    
    def generate(
        self,
        scan_id: str,
        input_text: str,
        vulnerabilities: List[Vulnerability],
        context: Optional[str] = None,
    ) -> ScanReport:
        """
        Generate scan report.
        
        Args:
            scan_id: Unique scan identifier
            input_text: Text that was scanned
            vulnerabilities: List of detected vulnerabilities
            context: Optional context
            
        Returns:
            ScanReport instance
        """
        report = ScanReport(
            scan_id=scan_id,
            input_text=input_text,
            vulnerabilities=vulnerabilities,
            context=context,
        )
        
        logger.info(f"Generated report {scan_id}: {len(vulnerabilities)} vulnerabilities")
        
        return report
    
    def save_json(
        self,
        report: ScanReport,
        filename: Optional[str] = None,
        include_input: bool = True,
    ) -> Path:
        """
        Save report as JSON file.
        
        Args:
            report: ScanReport instance
            filename: Output filename (default: scan_id.json)
            include_input: Whether to include input text
            
        Returns:
            Path to saved file
        """
        if filename is None:
            filename = f"{report.scan_id}.json"
        
        output_path = self.output_dir / filename
        
        with open(output_path, "w") as f:
            f.write(report.to_json(include_input=include_input))
        
        logger.info(f"Saved JSON report to {output_path}")
        
        return output_path
    
    def save_text(
        self,
        report: ScanReport,
        filename: Optional[str] = None,
    ) -> Path:
        """
        Save report as text file.
        
        Args:
            report: ScanReport instance
            filename: Output filename (default: scan_id.txt)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            filename = f"{report.scan_id}.txt"
        
        output_path = self.output_dir / filename
        
        with open(output_path, "w") as f:
            f.write(report.to_text())
        
        logger.info(f"Saved text report to {output_path}")
        
        return output_path
    
    def save_all_formats(
        self,
        report: ScanReport,
        prefix: Optional[str] = None,
    ) -> Dict[str, Path]:
        """
        Save report in all available formats.
        
        Args:
            report: ScanReport instance
            prefix: Filename prefix (default: scan_id)
            
        Returns:
            Dict mapping format to file path
        """
        prefix = prefix or report.scan_id
        
        results = {
            "json": self.save_json(report, f"{prefix}.json"),
            "text": self.save_text(report, f"{prefix}.txt"),
        }
        
        logger.info(f"Saved report in all formats under prefix: {prefix}")
        
        return results


class ReportAnalyzer:
    """Analyzes and compares scan reports."""
    
    @staticmethod
    def compare_reports(
        report1: ScanReport,
        report2: ScanReport,
    ) -> Dict[str, Any]:
        """
        Compare two scan reports.
        
        Args:
            report1: First report
            report2: Second report
            
        Returns:
            Comparison analysis
        """
        summary1 = report1.summary()
        summary2 = report2.summary()
        
        return {
            "total_change": summary2["total_vulnerabilities"] - summary1["total_vulnerabilities"],
            "severity_change": {
                severity: (summary2["severity_breakdown"][severity] - summary1["severity_breakdown"][severity])
                for severity in summary1["severity_breakdown"]
            },
            "new_types": set(summary2["type_breakdown"].keys()) - set(summary1["type_breakdown"].keys()),
            "resolved_types": set(summary1["type_breakdown"].keys()) - set(summary2["type_breakdown"].keys()),
        }
    
    @staticmethod
    def get_critical_vulnerabilities(report: ScanReport) -> List[Vulnerability]:
        """Extract critical vulnerabilities from report."""
        return [v for v in report.vulnerabilities if v.severity == SeverityLevel.CRITICAL]
    
    @staticmethod
    def get_remediation_summary(report: ScanReport) -> Dict[str, List[str]]:
        """Generate remediation summary grouped by type."""
        remediations = {}
        
        for vuln in report.vulnerabilities:
            type_name = vuln.type.value
            if type_name not in remediations:
                remediations[type_name] = []
            
            if vuln.remediation and vuln.remediation not in remediations[type_name]:
                remediations[type_name].append(vuln.remediation)
        
        return remediations
