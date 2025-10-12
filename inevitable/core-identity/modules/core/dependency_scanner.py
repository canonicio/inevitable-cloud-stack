"""
Dependency Vulnerability Scanner for Platform Forge
Addresses LOW-003: Dependency Vulnerability Scanning

Provides comprehensive dependency security scanning:
- Python package vulnerability detection
- Requirements file analysis
- Security advisory integration
- Automated vulnerability reporting
- Dependency license compliance
- Update recommendations
"""
import json
import re
import requests
import subprocess
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import pkg_resources
from packaging import version
import tempfile
import os

from .config import settings
from .security import SecurityError

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LicenseType(Enum):
    """Software license categories"""
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Vulnerability information"""
    id: str
    package_name: str
    affected_versions: str
    fixed_version: Optional[str]
    severity: VulnerabilitySeverity
    cve_ids: List[str] = field(default_factory=list)
    description: str = ""
    references: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None


@dataclass
class PackageInfo:
    """Package dependency information"""
    name: str
    version: str
    license: str
    license_type: LicenseType
    location: str
    dependencies: List[str] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    is_dev_dependency: bool = False
    last_updated: Optional[datetime] = None
    homepage: str = ""
    maintainer: str = ""


@dataclass
class ScanReport:
    """Complete vulnerability scan report"""
    timestamp: datetime
    total_packages: int
    vulnerable_packages: int
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[VulnerabilitySeverity, int]
    packages: List[PackageInfo]
    recommendations: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    scan_errors: List[str] = field(default_factory=list)


class DependencyVulnerabilityScanner:
    """
    Comprehensive dependency vulnerability scanner
    """
    
    def __init__(self):
        # Vulnerability databases
        self.vulnerability_sources = {
            "pypi_advisory": "https://pypi.org/pypi/{package}/json",
            "osv_api": "https://api.osv.dev/v1/query",
            "safety_db": "https://pyup.io/safety/",  # Placeholder for Safety DB
            "snyk_api": "https://api.snyk.io/v1/"   # Placeholder for Snyk API
        }
        
        # License classifications
        self.license_classifications = {
            # Permissive licenses
            "MIT": LicenseType.PERMISSIVE,
            "Apache": LicenseType.PERMISSIVE,
            "BSD": LicenseType.PERMISSIVE,
            "ISC": LicenseType.PERMISSIVE,
            "Unlicense": LicenseType.PERMISSIVE,
            
            # Copyleft licenses
            "GPL": LicenseType.COPYLEFT,
            "LGPL": LicenseType.COPYLEFT,
            "AGPL": LicenseType.COPYLEFT,
            "MPL": LicenseType.COPYLEFT,
            "EPL": LicenseType.COPYLEFT,
            
            # Proprietary
            "Proprietary": LicenseType.PROPRIETARY,
            "Commercial": LicenseType.PROPRIETARY
        }
        
        # Cache for API responses
        self.cache = {}
        self.cache_duration = timedelta(hours=6)
        
        # Known vulnerable patterns
        self.vulnerable_patterns = [
            r".*rc\d+",  # Release candidates
            r".*beta\d*",  # Beta versions
            r".*alpha\d*",  # Alpha versions
            r".*dev\d*",  # Development versions
        ]
    
    def scan_dependencies(
        self, 
        requirements_files: Optional[List[str]] = None,
        include_dev: bool = True
    ) -> ScanReport:
        """
        Perform comprehensive dependency vulnerability scan
        
        Args:
            requirements_files: List of requirements files to scan
            include_dev: Whether to include development dependencies
            
        Returns:
            Complete scan report with vulnerabilities and recommendations
        """
        start_time = datetime.utcnow()
        scan_errors = []
        
        try:
            logger.info("Starting dependency vulnerability scan")
            
            # Discover packages
            packages = self._discover_packages(requirements_files, include_dev)
            logger.info(f"Discovered {len(packages)} packages")
            
            # Scan each package for vulnerabilities
            for package in packages:
                try:
                    package.vulnerabilities = self._scan_package_vulnerabilities(package)
                    package.license_type = self._classify_license(package.license)
                except Exception as e:
                    error_msg = f"Error scanning package {package.name}: {e}"
                    scan_errors.append(error_msg)
                    logger.error(error_msg)
            
            # Generate report
            scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            vulnerable_packages = sum(1 for p in packages if p.vulnerabilities)
            total_vulnerabilities = sum(len(p.vulnerabilities) for p in packages)
            
            # Count vulnerabilities by severity
            severity_counts = {severity: 0 for severity in VulnerabilitySeverity}
            for package in packages:
                for vuln in package.vulnerabilities:
                    severity_counts[vuln.severity] += 1
            
            # Generate recommendations
            recommendations = self._generate_recommendations(packages)
            
            report = ScanReport(
                timestamp=start_time,
                total_packages=len(packages),
                vulnerable_packages=vulnerable_packages,
                total_vulnerabilities=total_vulnerabilities,
                vulnerabilities_by_severity=severity_counts,
                packages=packages,
                recommendations=recommendations,
                scan_duration=scan_duration,
                scan_errors=scan_errors
            )
            
            logger.info(f"Scan completed: {total_vulnerabilities} vulnerabilities found in {vulnerable_packages} packages")
            return report
            
        except Exception as e:
            logger.error(f"Dependency scan failed: {e}")
            raise SecurityError(f"Dependency vulnerability scan failed: {e}")
    
    def _discover_packages(
        self, 
        requirements_files: Optional[List[str]] = None,
        include_dev: bool = True
    ) -> List[PackageInfo]:
        """Discover installed packages and their information"""
        packages = []
        
        try:
            # Get currently installed packages
            installed_packages = {pkg.key: pkg for pkg in pkg_resources.working_set}
            
            # If requirements files provided, analyze them
            if requirements_files:
                requirements_packages = self._parse_requirements_files(requirements_files)
            else:
                requirements_packages = set(installed_packages.keys())
            
            for package_name in requirements_packages:
                try:
                    if package_name in installed_packages:
                        pkg = installed_packages[package_name]
                        
                        package_info = PackageInfo(
                            name=pkg.project_name,
                            version=pkg.version,
                            license=self._get_package_license(pkg),
                            license_type=LicenseType.UNKNOWN,  # Will be classified later
                            location=pkg.location,
                            dependencies=[str(req) for req in pkg.requires()],
                            is_dev_dependency=self._is_dev_dependency(pkg.project_name)
                        )
                        
                        packages.append(package_info)
                    else:
                        logger.warning(f"Package {package_name} not found in installed packages")
                        
                except Exception as e:
                    logger.error(f"Error processing package {package_name}: {e}")
            
            return packages
            
        except Exception as e:
            logger.error(f"Package discovery failed: {e}")
            return []
    
    def _parse_requirements_files(self, requirements_files: List[str]) -> Set[str]:
        """Parse requirements files to extract package names"""
        packages = set()
        
        for req_file in requirements_files:
            try:
                if os.path.exists(req_file):
                    with open(req_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Extract package name (before version specifiers)
                                package_name = re.split(r'[><=!]', line)[0].strip()
                                if package_name:
                                    packages.add(package_name.lower())
                else:
                    logger.warning(f"Requirements file not found: {req_file}")
                    
            except Exception as e:
                logger.error(f"Error parsing requirements file {req_file}: {e}")
        
        return packages
    
    def _get_package_license(self, pkg) -> str:
        """Extract license information from package metadata"""
        try:
            if hasattr(pkg, 'get_metadata'):
                metadata = pkg.get_metadata('METADATA') or pkg.get_metadata('PKG-INFO')
                if metadata:
                    for line in metadata.split('\n'):
                        if line.startswith('License:'):
                            return line.split(':', 1)[1].strip()
                        elif line.startswith('Classifier: License ::'):
                            return line.split('::')[-1].strip()
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def _classify_license(self, license_str: str) -> LicenseType:
        """Classify license type based on license string"""
        if not license_str or license_str.lower() in ["unknown", "none"]:
            return LicenseType.UNKNOWN
        
        license_lower = license_str.lower()
        
        for license_key, license_type in self.license_classifications.items():
            if license_key.lower() in license_lower:
                return license_type
        
        return LicenseType.UNKNOWN
    
    def _is_dev_dependency(self, package_name: str) -> bool:
        """Determine if package is likely a development dependency"""
        dev_keywords = [
            "test", "pytest", "unittest", "mock", "coverage", 
            "flake8", "pylint", "mypy", "black", "isort",
            "sphinx", "docs", "build", "setuptools", "wheel",
            "dev", "debug", "profile"
        ]
        
        package_lower = package_name.lower()
        return any(keyword in package_lower for keyword in dev_keywords)
    
    def _scan_package_vulnerabilities(self, package: PackageInfo) -> List[Vulnerability]:
        """Scan a specific package for known vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check OSV database
            osv_vulns = self._check_osv_database(package.name, package.version)
            vulnerabilities.extend(osv_vulns)
            
            # Check for vulnerable version patterns
            pattern_vulns = self._check_vulnerable_patterns(package.name, package.version)
            vulnerabilities.extend(pattern_vulns)
            
            # Check package metadata for security advisories
            metadata_vulns = self._check_package_metadata(package.name, package.version)
            vulnerabilities.extend(metadata_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {package.name}: {e}")
            return []
    
    def _check_osv_database(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check Open Source Vulnerabilities database"""
        vulnerabilities = []
        
        try:
            # Use cache if available
            cache_key = f"osv:{package_name}:{version}"
            if cache_key in self.cache:
                cache_entry = self.cache[cache_key]
                if datetime.utcnow() - cache_entry['timestamp'] < self.cache_duration:
                    return cache_entry['data']
            
            # Query OSV API
            query_data = {
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                }
            }
            
            response = requests.post(
                self.vulnerability_sources["osv_api"],
                json=query_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                for vuln_data in result.get('vulns', []):
                    vulnerability = self._parse_osv_vulnerability(vuln_data, package_name)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
            
            # Cache results
            self.cache[cache_key] = {
                'timestamp': datetime.utcnow(),
                'data': vulnerabilities
            }
            
        except requests.RequestException as e:
            logger.warning(f"OSV API request failed for {package_name}: {e}")
        except Exception as e:
            logger.error(f"OSV vulnerability check failed for {package_name}: {e}")
        
        return vulnerabilities
    
    def _parse_osv_vulnerability(self, vuln_data: Dict, package_name: str) -> Optional[Vulnerability]:
        """Parse OSV vulnerability data into Vulnerability object"""
        try:
            vuln_id = vuln_data.get('id', 'Unknown')
            summary = vuln_data.get('summary', '')
            details = vuln_data.get('details', '')
            
            # Extract severity (if available)
            severity = VulnerabilitySeverity.MEDIUM  # Default
            if 'severity' in vuln_data:
                severity_str = vuln_data['severity'][0].get('score', 'MEDIUM')
                try:
                    severity = VulnerabilitySeverity(severity_str.lower())
                except ValueError:
                    severity = VulnerabilitySeverity.MEDIUM
            
            # Extract affected versions
            affected_versions = "Unknown"
            fixed_version = None
            
            for affected in vuln_data.get('affected', []):
                if affected.get('package', {}).get('name') == package_name:
                    ranges = affected.get('ranges', [])
                    if ranges:
                        affected_versions = str(ranges[0])
                    
                    # Look for fixed version
                    database_specific = affected.get('database_specific', {})
                    fixed_version = database_specific.get('fixed_version')
            
            # Extract CVE IDs
            cve_ids = []
            for alias in vuln_data.get('aliases', []):
                if alias.startswith('CVE-'):
                    cve_ids.append(alias)
            
            # Extract references
            references = [ref.get('url', '') for ref in vuln_data.get('references', [])]
            
            return Vulnerability(
                id=vuln_id,
                package_name=package_name,
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                severity=severity,
                cve_ids=cve_ids,
                description=f"{summary}. {details}".strip(),
                references=references,
                published_date=self._parse_date(vuln_data.get('published')),
                last_modified=self._parse_date(vuln_data.get('modified'))
            )
            
        except Exception as e:
            logger.error(f"Error parsing OSV vulnerability: {e}")
            return None
    
    def _check_vulnerable_patterns(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check for vulnerable version patterns (pre-release, etc.)"""
        vulnerabilities = []
        
        for pattern in self.vulnerable_patterns:
            if re.match(pattern, version):
                vulnerability = Vulnerability(
                    id=f"PATTERN-{package_name}-{version}",
                    package_name=package_name,
                    affected_versions=version,
                    fixed_version=None,
                    severity=VulnerabilitySeverity.LOW,
                    description=f"Pre-release or development version detected: {version}. Consider using stable release.",
                    references=[]
                )
                vulnerabilities.append(vulnerability)
                break
        
        return vulnerabilities
    
    def _check_package_metadata(self, package_name: str, version: str) -> List[Vulnerability]:
        """Check package metadata for security information"""
        vulnerabilities = []
        
        try:
            # This would integrate with PyPI API or other metadata sources
            # For now, this is a placeholder for additional checks
            
            # Example: Check if package has been deprecated or abandoned
            # Example: Check for known malicious packages
            # Example: Check package maintainer reputation
            
            pass
            
        except Exception as e:
            logger.error(f"Package metadata check failed for {package_name}: {e}")
        
        return vulnerabilities
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string into datetime object"""
        if not date_str:
            return None
        
        try:
            # Handle various date formats
            for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                try:
                    return datetime.strptime(date_str.split('.')[0], fmt)
                except ValueError:
                    continue
            return None
        except Exception:
            return None
    
    def _generate_recommendations(self, packages: List[PackageInfo]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Count vulnerabilities by severity
        critical_count = sum(len([v for v in p.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]) for p in packages)
        high_count = sum(len([v for v in p.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]) for p in packages)
        medium_count = sum(len([v for v in p.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM]) for p in packages)
        
        # Critical recommendations
        if critical_count > 0:
            recommendations.append(f"URGENT: {critical_count} critical vulnerabilities found. Update immediately.")
        
        if high_count > 0:
            recommendations.append(f"HIGH PRIORITY: {high_count} high-severity vulnerabilities detected.")
        
        if medium_count > 5:
            recommendations.append(f"Consider updating packages with {medium_count} medium-severity vulnerabilities.")
        
        # License recommendations
        copyleft_packages = [p for p in packages if p.license_type == LicenseType.COPYLEFT]
        if copyleft_packages:
            recommendations.append(f"Review {len(copyleft_packages)} packages with copyleft licenses for compliance.")
        
        unknown_license_packages = [p for p in packages if p.license_type == LicenseType.UNKNOWN]
        if len(unknown_license_packages) > 10:
            recommendations.append(f"Verify licenses for {len(unknown_license_packages)} packages with unknown licenses.")
        
        # Development dependency recommendations
        vulnerable_dev_packages = [p for p in packages if p.is_dev_dependency and p.vulnerabilities]
        if vulnerable_dev_packages:
            recommendations.append(f"Update {len(vulnerable_dev_packages)} vulnerable development dependencies.")
        
        # Version pattern recommendations
        prerelease_packages = []
        for package in packages:
            for pattern in self.vulnerable_patterns:
                if re.match(pattern, package.version):
                    prerelease_packages.append(package)
                    break
        
        if prerelease_packages:
            recommendations.append(f"Consider upgrading {len(prerelease_packages)} pre-release packages to stable versions.")
        
        # General recommendations
        if not recommendations:
            recommendations.append("No immediate security concerns detected. Continue regular dependency monitoring.")
        else:
            recommendations.append("Implement automated dependency scanning in CI/CD pipeline.")
            recommendations.append("Set up vulnerability alerts for critical dependencies.")
        
        return recommendations
    
    def export_report(self, report: ScanReport, format: str = "json") -> str:
        """Export scan report in specified format"""
        try:
            if format.lower() == "json":
                return self._export_json_report(report)
            elif format.lower() == "csv":
                return self._export_csv_report(report)
            elif format.lower() == "html":
                return self._export_html_report(report)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Report export failed: {e}")
            raise SecurityError(f"Failed to export report: {e}")
    
    def _export_json_report(self, report: ScanReport) -> str:
        """Export report as JSON"""
        def serialize_enum(obj):
            if isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        report_dict = {
            "timestamp": report.timestamp.isoformat(),
            "summary": {
                "total_packages": report.total_packages,
                "vulnerable_packages": report.vulnerable_packages,
                "total_vulnerabilities": report.total_vulnerabilities,
                "scan_duration": report.scan_duration
            },
            "vulnerabilities_by_severity": {
                severity.value: count for severity, count in report.vulnerabilities_by_severity.items()
            },
            "packages": [
                {
                    "name": pkg.name,
                    "version": pkg.version,
                    "license": pkg.license,
                    "license_type": pkg.license_type.value,
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "severity": v.severity.value,
                            "description": v.description,
                            "cve_ids": v.cve_ids,
                            "fixed_version": v.fixed_version
                        }
                        for v in pkg.vulnerabilities
                    ]
                }
                for pkg in report.packages if pkg.vulnerabilities
            ],
            "recommendations": report.recommendations,
            "scan_errors": report.scan_errors
        }
        
        return json.dumps(report_dict, indent=2, default=serialize_enum)
    
    def _export_csv_report(self, report: ScanReport) -> str:
        """Export report as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Package", "Version", "License", "Vulnerability ID", 
            "Severity", "Description", "CVE IDs", "Fixed Version"
        ])
        
        # Data rows
        for pkg in report.packages:
            if pkg.vulnerabilities:
                for vuln in pkg.vulnerabilities:
                    writer.writerow([
                        pkg.name,
                        pkg.version,
                        pkg.license,
                        vuln.id,
                        vuln.severity.value,
                        vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description,
                        "; ".join(vuln.cve_ids),
                        vuln.fixed_version or "N/A"
                    ])
            else:
                writer.writerow([
                    pkg.name,
                    pkg.version,
                    pkg.license,
                    "No vulnerabilities",
                    "N/A",
                    "No known vulnerabilities",
                    "",
                    ""
                ])
        
        return output.getvalue()
    
    def _export_html_report(self, report: ScanReport) -> str:
        """Export report as HTML"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dependency Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
                .recommendations {{ background-color: #e8f5e8; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Dependency Vulnerability Scan Report</h1>
                <p>Generated on: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p>Scan Duration: {report.scan_duration:.2f} seconds</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <ul>
                    <li>Total Packages: {report.total_packages}</li>
                    <li>Vulnerable Packages: {report.vulnerable_packages}</li>
                    <li>Total Vulnerabilities: {report.total_vulnerabilities}</li>
                </ul>
            </div>
            
            <div class="vulnerabilities">
                <h2>Vulnerabilities by Severity</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    {"".join(f'<tr><td class="{sev.value}">{sev.value.upper()}</td><td>{count}</td></tr>' 
                            for sev, count in report.vulnerabilities_by_severity.items() if count > 0)}
                </table>
            </div>
            
            <div class="packages">
                <h2>Vulnerable Packages</h2>
                <table>
                    <tr><th>Package</th><th>Version</th><th>License</th><th>Vulnerabilities</th></tr>
                    {"".join(f'<tr><td>{pkg.name}</td><td>{pkg.version}</td><td>{pkg.license}</td><td>{len(pkg.vulnerabilities)}</td></tr>' 
                            for pkg in report.packages if pkg.vulnerabilities)}
                </table>
            </div>
            
            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
                    {"".join(f'<li>{rec}</li>' for rec in report.recommendations)}
                </ul>
            </div>
        </body>
        </html>
        """
        
        return html_template


# Global dependency scanner instance
_dependency_scanner = None


def get_dependency_scanner() -> DependencyVulnerabilityScanner:
    """Get global dependency vulnerability scanner instance"""
    global _dependency_scanner
    if _dependency_scanner is None:
        _dependency_scanner = DependencyVulnerabilityScanner()
    return _dependency_scanner