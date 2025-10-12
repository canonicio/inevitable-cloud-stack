"""
Comprehensive Supply Chain Security System
Addresses RISK-M003: Supply Chain Vulnerabilities

This module provides:
1. Dependency vulnerability scanning
2. Package integrity verification
3. License compliance checking
4. Malicious package detection
5. Software Bill of Materials (SBOM) generation
6. Runtime dependency monitoring
"""

import json
import hashlib
import os
import subprocess
import tempfile
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import pkg_resources
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LicenseRisk(Enum):
    """License risk levels"""
    SAFE = "safe"
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class PackageRisk(Enum):
    """Package risk assessment"""
    TRUSTED = "trusted"
    VERIFIED = "verified"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Represents a security vulnerability in a package"""
    id: str
    package_name: str
    package_version: str
    severity: VulnerabilitySeverity
    title: str
    description: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    fixed_versions: List[str]
    published_date: Optional[datetime]
    references: List[str]


@dataclass
class PackageInfo:
    """Information about a package in the supply chain"""
    name: str
    version: str
    license: Optional[str]
    license_risk: LicenseRisk
    homepage: Optional[str]
    repository: Optional[str]
    author: Optional[str]
    description: Optional[str]
    dependencies: List[str]
    file_hashes: Dict[str, str]
    install_path: Optional[str]
    last_updated: Optional[datetime]
    download_count: Optional[int]
    maintainers: List[str]
    risk_score: float
    risk_assessment: PackageRisk
    vulnerabilities: List[Vulnerability]


@dataclass
class SupplyChainReport:
    """Comprehensive supply chain security report"""
    scan_timestamp: datetime
    total_packages: int
    vulnerable_packages: int
    high_risk_packages: int
    license_violations: int
    packages: List[PackageInfo]
    vulnerabilities: List[Vulnerability]
    recommendations: List[str]
    sbom: Dict[str, Any]
    risk_score: float


class SupplyChainSecurityConfig:
    """Configuration for supply chain security system"""
    
    # Vulnerability databases to query
    VULNERABILITY_DATABASES = {
        "osv": "https://osv.dev/v1/query",
        "safety": "https://pyup.io/safety/api/v1/",
        "snyk": "https://snyk.io/api/v1/"  # Requires API key
    }
    
    # License categories and risk levels
    LICENSE_CLASSIFICATIONS = {
        # Safe licenses (permissive, business-friendly)
        "safe": {
            "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", 
            "ISC", "Unlicense", "WTFPL"
        },
        # Permissive but may require attribution
        "permissive": {
            "Apache License", "Apache Software License", "BSD License",
            "MIT License", "X11", "Zlib"
        },
        # Copyleft licenses (require source disclosure)
        "copyleft": {
            "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", 
            "MPL-2.0", "EPL-1.0", "EPL-2.0"
        },
        # Restricted or problematic licenses
        "restricted": {
            "AGPL-3.0", "GPL-2.0+", "GPL-3.0+", "SSPL-1.0",
            "Commons Clause", "Elastic License"
        }
    }
    
    # Suspicious package patterns
    SUSPICIOUS_PATTERNS = {
        "name_typosquatting": [
            r".*requests.*", r".*urllib.*", r".*numpy.*",
            r".*pandas.*", r".*django.*", r".*flask.*"
        ],
        "suspicious_descriptions": [
            r"test.*package", r".*backdoor.*", r".*malware.*",
            r".*crypto.*miner", r".*bitcoin.*", r".*mining.*"
        ],
        "suspicious_authors": [
            "test", "admin", "user", "demo", "example"
        ]
    }
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        "vulnerability_count": 0.3,
        "vulnerability_severity": 0.25,
        "license_risk": 0.15,
        "package_age": 0.1,
        "maintainer_trust": 0.1,
        "download_popularity": 0.05,
        "dependency_depth": 0.05
    }
    
    # Cache durations
    VULNERABILITY_CACHE_HOURS = 6
    PACKAGE_INFO_CACHE_HOURS = 24
    
    # Rate limiting
    API_RATE_LIMIT_SECONDS = 1


class SupplyChainScanner:
    """
    Comprehensive supply chain security scanner
    
    Features:
    - Multi-source vulnerability scanning
    - Package integrity verification
    - License compliance analysis
    - Malicious package detection
    - SBOM generation
    - Risk scoring and recommendations
    """
    
    def __init__(self, config: Optional[SupplyChainSecurityConfig] = None):
        self.config = config or SupplyChainSecurityConfig()
        self.cache_dir = Path.home() / ".platformforge_security" / "supply_chain"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize vulnerability databases
        self.vuln_databases = self.config.VULNERABILITY_DATABASES
        self.last_api_call = 0
        
        # Package cache
        self.package_cache = {}
        self.vulnerability_cache = {}
        
        logger.info("Supply chain security scanner initialized")
    
    def scan_dependencies(self, requirements_path: Optional[str] = None) -> SupplyChainReport:
        """
        Perform comprehensive supply chain security scan
        
        Args:
            requirements_path: Path to requirements.txt file, or None for installed packages
            
        Returns:
            Detailed security report
        """
        logger.info("Starting comprehensive supply chain security scan")
        start_time = datetime.utcnow()
        
        # Get list of packages to scan
        if requirements_path and os.path.exists(requirements_path):
            packages = self._parse_requirements_file(requirements_path)
        else:
            packages = self._get_installed_packages()
        
        logger.info(f"Scanning {len(packages)} packages for vulnerabilities")
        
        # Scan each package
        scanned_packages = []
        all_vulnerabilities = []
        
        for package_name, package_version in packages:
            try:
                package_info = self._analyze_package(package_name, package_version)
                scanned_packages.append(package_info)
                all_vulnerabilities.extend(package_info.vulnerabilities)
                
                # Rate limiting
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error analyzing package {package_name}: {e}")
                # Create minimal package info for failed scans
                failed_package = PackageInfo(
                    name=package_name,
                    version=package_version,
                    license=None,
                    license_risk=LicenseRisk.UNKNOWN,
                    homepage=None,
                    repository=None,
                    author=None,
                    description=None,
                    dependencies=[],
                    file_hashes={},
                    install_path=None,
                    last_updated=None,
                    download_count=None,
                    maintainers=[],
                    risk_score=5.0,  # High risk for failed scans
                    risk_assessment=PackageRisk.UNKNOWN,
                    vulnerabilities=[]
                )
                scanned_packages.append(failed_package)
        
        # Generate report
        report = self._generate_report(
            packages=scanned_packages,
            vulnerabilities=all_vulnerabilities,
            scan_start=start_time
        )
        
        logger.info(f"Supply chain scan completed. Found {len(all_vulnerabilities)} vulnerabilities in {len(scanned_packages)} packages")
        return report
    
    def _parse_requirements_file(self, requirements_path: str) -> List[Tuple[str, str]]:
        """Parse requirements.txt file"""
        packages = []
        
        try:
            with open(requirements_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple parsing - can be enhanced for complex requirements
                        if '==' in line:
                            name, version = line.split('==', 1)
                            packages.append((name.strip(), version.strip()))
                        elif '>=' in line:
                            name = line.split('>=', 1)[0].strip()
                            packages.append((name, "latest"))
                        else:
                            packages.append((line.strip(), "latest"))
        except Exception as e:
            logger.error(f"Error parsing requirements file: {e}")
        
        return packages
    
    def _get_installed_packages(self) -> List[Tuple[str, str]]:
        """Get list of installed packages"""
        packages = []
        
        try:
            for dist in pkg_resources.working_set:
                packages.append((dist.project_name, dist.version))
        except Exception as e:
            logger.error(f"Error getting installed packages: {e}")
        
        return packages
    
    def _analyze_package(self, package_name: str, package_version: str) -> PackageInfo:
        """Perform comprehensive analysis of a single package"""
        
        # Get package metadata
        metadata = self._get_package_metadata(package_name, package_version)
        
        # Check for vulnerabilities
        vulnerabilities = self._check_vulnerabilities(package_name, package_version)
        
        # Assess license risk
        license_risk = self._assess_license_risk(metadata.get('license'))
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            package_name=package_name,
            metadata=metadata,
            vulnerabilities=vulnerabilities,
            license_risk=license_risk
        )
        
        # Assess overall package risk
        risk_assessment = self._assess_package_risk(
            package_name=package_name,
            metadata=metadata,
            vulnerabilities=vulnerabilities,
            risk_score=risk_score
        )
        
        # Get file hashes for integrity verification
        file_hashes = self._get_package_file_hashes(package_name)
        
        return PackageInfo(
            name=package_name,
            version=package_version,
            license=metadata.get('license'),
            license_risk=license_risk,
            homepage=metadata.get('homepage'),
            repository=metadata.get('repository'),
            author=metadata.get('author'),
            description=metadata.get('description'),
            dependencies=metadata.get('dependencies', []),
            file_hashes=file_hashes,
            install_path=metadata.get('install_path'),
            last_updated=metadata.get('last_updated'),
            download_count=metadata.get('download_count'),
            maintainers=metadata.get('maintainers', []),
            risk_score=risk_score,
            risk_assessment=risk_assessment,
            vulnerabilities=vulnerabilities
        )
    
    def _get_package_metadata(self, package_name: str, package_version: str) -> Dict[str, Any]:
        """Get comprehensive package metadata"""
        metadata = {}
        
        try:
            # Try to get from installed packages first
            try:
                dist = pkg_resources.get_distribution(package_name)
                metadata.update({
                    'version': dist.version,
                    'install_path': dist.location,
                    'dependencies': [str(req) for req in dist.requires()],
                })
                
                # Get metadata from distribution
                if hasattr(dist, 'get_metadata'):
                    meta_text = dist.get_metadata('METADATA')
                    metadata.update(self._parse_metadata_text(meta_text))
                
            except pkg_resources.DistributionNotFound:
                pass
            
            # Try to get from PyPI API
            pypi_data = self._fetch_pypi_metadata(package_name)
            if pypi_data:
                metadata.update(pypi_data)
                
        except Exception as e:
            logger.warning(f"Error getting metadata for {package_name}: {e}")
        
        return metadata
    
    def _fetch_pypi_metadata(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Fetch metadata from PyPI API with caching"""
        cache_key = f"pypi_{package_name}"
        cached = self._get_from_cache(cache_key, self.config.PACKAGE_INFO_CACHE_HOURS)
        
        if cached:
            return cached
        
        try:
            # Rate limiting
            self._rate_limit()
            
            url = f"https://pypi.org/pypi/{package_name}/json"
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
            
            # Extract relevant metadata
            info = data.get('info', {})
            metadata = {
                'license': info.get('license'),
                'homepage': info.get('home_page'),
                'repository': info.get('project_url', {}).get('Repository'),
                'author': info.get('author'),
                'description': info.get('summary'),
                'last_updated': info.get('upload_time'),
                'maintainers': [info.get('author')] if info.get('author') else [],
                'download_count': self._get_download_stats(package_name)
            }
            
            # Cache the result
            self._save_to_cache(cache_key, metadata)
            return metadata
            
        except Exception as e:
            logger.warning(f"Error fetching PyPI metadata for {package_name}: {e}")
            return None
    
    def _parse_metadata_text(self, metadata_text: str) -> Dict[str, Any]:
        """Parse package metadata text"""
        metadata = {}
        
        for line in metadata_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace('-', '_')
                value = value.strip()
                
                if key in ['license', 'author', 'home_page', 'summary']:
                    metadata[key.replace('home_page', 'homepage').replace('summary', 'description')] = value
        
        return metadata
    
    def _check_vulnerabilities(self, package_name: str, package_version: str) -> List[Vulnerability]:
        """Check for known vulnerabilities across multiple databases"""
        cache_key = f"vulns_{package_name}_{package_version}"
        cached = self._get_from_cache(cache_key, self.config.VULNERABILITY_CACHE_HOURS)
        
        if cached:
            return [Vulnerability(**v) for v in cached]
        
        all_vulnerabilities = []
        
        # Check OSV database
        osv_vulns = self._check_osv_vulnerabilities(package_name, package_version)
        all_vulnerabilities.extend(osv_vulns)
        
        # Check Safety DB (if available)
        safety_vulns = self._check_safety_vulnerabilities(package_name, package_version)
        all_vulnerabilities.extend(safety_vulns)
        
        # Deduplicate vulnerabilities
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        # Cache results
        vuln_data = [asdict(v) for v in unique_vulnerabilities]
        self._save_to_cache(cache_key, vuln_data)
        
        return unique_vulnerabilities
    
    def _check_osv_vulnerabilities(self, package_name: str, package_version: str) -> List[Vulnerability]:
        """Check OSV (Open Source Vulnerabilities) database"""
        vulnerabilities = []
        
        try:
            # Rate limiting
            self._rate_limit()
            
            query_data = {
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": package_version
            }
            
            req = urllib.request.Request(
                self.vuln_databases["osv"],
                data=json.dumps(query_data).encode(),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
            
            # Parse vulnerability data
            for vuln in data.get('vulns', []):
                vulnerability = Vulnerability(
                    id=vuln.get('id', 'OSV-UNKNOWN'),
                    package_name=package_name,
                    package_version=package_version,
                    severity=self._parse_severity(vuln.get('severity', [])),
                    title=vuln.get('summary', 'Unknown vulnerability'),
                    description=vuln.get('details', ''),
                    cve_ids=[alias for alias in vuln.get('aliases', []) if alias.startswith('CVE-')],
                    cvss_score=self._extract_cvss_score(vuln),
                    fixed_versions=self._extract_fixed_versions(vuln),
                    published_date=self._parse_date(vuln.get('published')),
                    references=[ref.get('url') for ref in vuln.get('references', [])]
                )
                vulnerabilities.append(vulnerability)
                
        except Exception as e:
            logger.warning(f"Error checking OSV vulnerabilities for {package_name}: {e}")
        
        return vulnerabilities
    
    def _check_safety_vulnerabilities(self, package_name: str, package_version: str) -> List[Vulnerability]:
        """Check Safety database (simplified implementation)"""
        # In a production implementation, this would integrate with Safety CLI
        # or their API. For now, return empty list
        return []
    
    def _assess_license_risk(self, license_str: Optional[str]) -> LicenseRisk:
        """Assess risk level of a software license"""
        if not license_str:
            return LicenseRisk.UNKNOWN
        
        license_lower = license_str.lower()
        
        # Check each category
        for category, licenses in self.config.LICENSE_CLASSIFICATIONS.items():
            for license_pattern in licenses:
                if license_pattern.lower() in license_lower:
                    return LicenseRisk(category)
        
        # Default to unknown for unrecognized licenses
        return LicenseRisk.UNKNOWN
    
    def _calculate_risk_score(self, package_name: str, metadata: Dict, 
                            vulnerabilities: List[Vulnerability], 
                            license_risk: LicenseRisk) -> float:
        """Calculate overall risk score for a package (0-10 scale)"""
        
        risk_factors = {
            'vulnerability_count': min(len(vulnerabilities), 10),
            'vulnerability_severity': self._get_max_vulnerability_severity_score(vulnerabilities),
            'license_risk': self._get_license_risk_score(license_risk),
            'package_age': self._get_package_age_score(metadata.get('last_updated')),
            'maintainer_trust': self._get_maintainer_trust_score(metadata.get('maintainers', [])),
            'download_popularity': self._get_popularity_score(metadata.get('download_count')),
            'dependency_depth': self._get_dependency_depth_score(metadata.get('dependencies', []))
        }
        
        # Calculate weighted score
        total_score = 0
        for factor, score in risk_factors.items():
            weight = self.config.RISK_WEIGHTS.get(factor, 0.1)
            total_score += score * weight
        
        return min(total_score, 10.0)  # Cap at 10
    
    def _assess_package_risk(self, package_name: str, metadata: Dict,
                           vulnerabilities: List[Vulnerability], risk_score: float) -> PackageRisk:
        """Assess overall package risk level"""
        
        # Check for malicious patterns
        if self._is_suspicious_package(package_name, metadata):
            return PackageRisk.MALICIOUS
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]
        if critical_vulns:
            return PackageRisk.SUSPICIOUS
        
        # Risk score based assessment
        if risk_score >= 8.0:
            return PackageRisk.SUSPICIOUS
        elif risk_score >= 5.0:
            return PackageRisk.VERIFIED
        elif risk_score <= 2.0:
            return PackageRisk.TRUSTED
        else:
            return PackageRisk.VERIFIED
    
    def _is_suspicious_package(self, package_name: str, metadata: Dict) -> bool:
        """Check if package shows signs of being malicious"""
        
        # Check for typosquatting
        for pattern in self.config.SUSPICIOUS_PATTERNS['name_typosquatting']:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        
        # Check description for suspicious content
        description = metadata.get('description', '').lower()
        for pattern in self.config.SUSPICIOUS_PATTERNS['suspicious_descriptions']:
            if re.search(pattern, description, re.IGNORECASE):
                return True
        
        # Check author
        author = metadata.get('author', '').lower()
        if author in self.config.SUSPICIOUS_PATTERNS['suspicious_authors']:
            return True
        
        return False
    
    def _get_package_file_hashes(self, package_name: str) -> Dict[str, str]:
        """Get file hashes for package integrity verification"""
        hashes = {}
        
        try:
            dist = pkg_resources.get_distribution(package_name)
            if hasattr(dist, 'location'):
                package_path = Path(dist.location)
                if package_path.exists():
                    for file_path in package_path.rglob('*.py'):
                        if file_path.is_file():
                            try:
                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                    relative_path = str(file_path.relative_to(package_path))
                                    hashes[relative_path] = file_hash
                            except Exception:
                                continue
        except Exception as e:
            logger.warning(f"Error computing file hashes for {package_name}: {e}")
        
        return hashes
    
    def _generate_report(self, packages: List[PackageInfo], vulnerabilities: List[Vulnerability],
                        scan_start: datetime) -> SupplyChainReport:
        """Generate comprehensive supply chain security report"""
        
        # Calculate statistics
        total_packages = len(packages)
        vulnerable_packages = len([p for p in packages if p.vulnerabilities])
        high_risk_packages = len([p for p in packages if p.risk_score >= 7.0])
        license_violations = len([p for p in packages if p.license_risk in [LicenseRisk.RESTRICTED, LicenseRisk.COPYLEFT]])
        
        # Generate recommendations
        recommendations = self._generate_recommendations(packages, vulnerabilities)
        
        # Generate SBOM
        sbom = self._generate_sbom(packages)
        
        # Calculate overall risk score
        if packages:
            avg_risk = sum(p.risk_score for p in packages) / len(packages)
            risk_score = min(avg_risk + (len(vulnerabilities) * 0.1), 10.0)
        else:
            risk_score = 0.0
        
        return SupplyChainReport(
            scan_timestamp=scan_start,
            total_packages=total_packages,
            vulnerable_packages=vulnerable_packages,
            high_risk_packages=high_risk_packages,
            license_violations=license_violations,
            packages=packages,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            sbom=sbom,
            risk_score=risk_score
        )
    
    def _generate_recommendations(self, packages: List[PackageInfo], vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Vulnerability-based recommendations
        critical_vulns = [v for v in vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]
        if critical_vulns:
            recommendations.append(f"URGENT: Address {len(critical_vulns)} critical vulnerabilities immediately")
        
        high_vulns = [v for v in vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]
        if high_vulns:
            recommendations.append(f"Update packages to fix {len(high_vulns)} high-severity vulnerabilities")
        
        # Package-based recommendations
        suspicious_packages = [p for p in packages if p.risk_assessment == PackageRisk.SUSPICIOUS]
        if suspicious_packages:
            recommendations.append(f"Review {len(suspicious_packages)} suspicious packages for potential threats")
        
        # License-based recommendations
        restricted_licenses = [p for p in packages if p.license_risk == LicenseRisk.RESTRICTED]
        if restricted_licenses:
            recommendations.append(f"Review {len(restricted_licenses)} packages with restricted licenses")
        
        # General recommendations
        recommendations.append("Implement automated dependency scanning in CI/CD pipeline")
        recommendations.append("Enable vulnerability alerts and automatic updates where possible")
        recommendations.append("Regularly audit and minimize dependencies")
        
        return recommendations
    
    def _generate_sbom(self, packages: List[PackageInfo]) -> Dict[str, Any]:
        """Generate Software Bill of Materials (SBOM) in SPDX-like format"""
        
        sbom = {
            "spdxVersion": "SPDX-2.2",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Platform Forge Supply Chain SBOM",
            "documentNamespace": f"https://platformforge.dev/sbom/{int(time.time())}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: Platform Forge Supply Chain Scanner"]
            },
            "packages": []
        }
        
        for package in packages:
            sbom_package = {
                "SPDXID": f"SPDXRef-Package-{package.name}",
                "name": package.name,
                "versionInfo": package.version,
                "downloadLocation": package.homepage or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": package.license or "NOASSERTION",
                "licenseDeclared": package.license or "NOASSERTION",
                "copyrightText": f"Copyright {package.author}" if package.author else "NOASSERTION",
                "supplier": f"Person: {package.author}" if package.author else "NOASSERTION",
                "externalRefs": []
            }
            
            # Add vulnerability references
            for vuln in package.vulnerabilities:
                sbom_package["externalRefs"].append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": vuln.id
                })
            
            sbom["packages"].append(sbom_package)
        
        return sbom
    
    # Helper methods for risk scoring
    def _get_max_vulnerability_severity_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Get score based on maximum vulnerability severity"""
        if not vulnerabilities:
            return 0.0
        
        severity_scores = {
            VulnerabilitySeverity.CRITICAL: 10.0,
            VulnerabilitySeverity.HIGH: 7.0,
            VulnerabilitySeverity.MEDIUM: 4.0,
            VulnerabilitySeverity.LOW: 2.0,
            VulnerabilitySeverity.UNKNOWN: 1.0
        }
        
        max_severity = max(v.severity for v in vulnerabilities)
        return severity_scores.get(max_severity, 1.0)
    
    def _get_license_risk_score(self, license_risk: LicenseRisk) -> float:
        """Get risk score based on license"""
        scores = {
            LicenseRisk.SAFE: 0.0,
            LicenseRisk.PERMISSIVE: 1.0,
            LicenseRisk.COPYLEFT: 3.0,
            LicenseRisk.RESTRICTED: 6.0,
            LicenseRisk.UNKNOWN: 2.0
        }
        return scores.get(license_risk, 2.0)
    
    def _get_package_age_score(self, last_updated: Optional[str]) -> float:
        """Get risk score based on package age"""
        if not last_updated:
            return 3.0
        
        try:
            update_date = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
            days_old = (datetime.utcnow() - update_date.replace(tzinfo=None)).days
            
            if days_old < 30:
                return 0.0
            elif days_old < 180:
                return 1.0
            elif days_old < 365:
                return 2.0
            else:
                return 4.0
        except:
            return 3.0
    
    def _get_maintainer_trust_score(self, maintainers: List[str]) -> float:
        """Get trust score based on maintainers"""
        if not maintainers:
            return 5.0
        
        # Simple heuristic - can be enhanced with maintainer reputation data
        known_maintainers = len([m for m in maintainers if len(m) > 3 and '@' in m])
        if known_maintainers > 0:
            return max(0.0, 3.0 - known_maintainers)
        else:
            return 4.0
    
    def _get_popularity_score(self, download_count: Optional[int]) -> float:
        """Get score based on package popularity"""
        if not download_count:
            return 3.0
        
        if download_count > 1000000:  # 1M+ downloads
            return 0.0
        elif download_count > 100000:  # 100K+ downloads
            return 1.0
        elif download_count > 10000:   # 10K+ downloads
            return 2.0
        else:
            return 4.0
    
    def _get_dependency_depth_score(self, dependencies: List[str]) -> float:
        """Get risk score based on number of dependencies"""
        dep_count = len(dependencies)
        
        if dep_count == 0:
            return 0.0
        elif dep_count < 5:
            return 1.0
        elif dep_count < 15:
            return 2.0
        else:
            return 4.0
    
    # Utility methods
    def _parse_severity(self, severity_data: List[Dict]) -> VulnerabilitySeverity:
        """Parse vulnerability severity from various formats"""
        if not severity_data:
            return VulnerabilitySeverity.UNKNOWN
        
        for sev in severity_data:
            score = sev.get('score', '').upper()
            if score in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                return VulnerabilitySeverity(score.lower())
        
        return VulnerabilitySeverity.UNKNOWN
    
    def _extract_cvss_score(self, vuln_data: Dict) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        try:
            severity = vuln_data.get('severity', [])
            for sev in severity:
                if 'CVSS' in sev.get('type', ''):
                    return float(sev.get('score', 0))
        except:
            pass
        return None
    
    def _extract_fixed_versions(self, vuln_data: Dict) -> List[str]:
        """Extract fixed versions from vulnerability data"""
        fixed_versions = []
        
        try:
            affected = vuln_data.get('affected', [])
            for affect in affected:
                ranges = affect.get('ranges', [])
                for range_data in ranges:
                    events = range_data.get('events', [])
                    for event in events:
                        if event.get('fixed'):
                            fixed_versions.append(event['fixed'])
        except:
            pass
        
        return fixed_versions
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse various date formats"""
        if not date_str:
            return None
        
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00')).replace(tzinfo=None)
        except:
            return None
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Use CVE ID if available, otherwise use vulnerability ID
            key = vuln.cve_ids[0] if vuln.cve_ids else vuln.id
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def _rate_limit(self):
        """Implement rate limiting for API calls"""
        now = time.time()
        time_since_last = now - self.last_api_call
        if time_since_last < self.config.API_RATE_LIMIT_SECONDS:
            time.sleep(self.config.API_RATE_LIMIT_SECONDS - time_since_last)
        self.last_api_call = time.time()
    
    def _get_from_cache(self, key: str, max_age_hours: int) -> Optional[Any]:
        """Get data from cache if not expired"""
        cache_file = self.cache_dir / f"{key}.json"
        
        try:
            if cache_file.exists():
                stat = cache_file.stat()
                age_hours = (time.time() - stat.st_mtime) / 3600
                
                if age_hours < max_age_hours:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
        except Exception:
            pass
        
        return None
    
    def _save_to_cache(self, key: str, data: Any):
        """Save data to cache"""
        cache_file = self.cache_dir / f"{key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, default=str)
        except Exception as e:
            logger.warning(f"Error saving to cache: {e}")
    
    def _get_download_stats(self, package_name: str) -> Optional[int]:
        """Get package download statistics (simplified)"""
        # In production, this could query PyPI stats API or similar
        return None


# Supply chain security middleware and monitoring
class SupplyChainMonitor:
    """Runtime monitoring for supply chain security"""
    
    def __init__(self, scanner: SupplyChainScanner):
        self.scanner = scanner
        self.baseline_report = None
        self.monitoring_active = False
    
    def establish_baseline(self) -> SupplyChainReport:
        """Establish security baseline for monitoring"""
        self.baseline_report = self.scanner.scan_dependencies()
        return self.baseline_report
    
    def detect_changes(self) -> Dict[str, Any]:
        """Detect changes in supply chain since baseline"""
        if not self.baseline_report:
            raise ValueError("No baseline established")
        
        current_report = self.scanner.scan_dependencies()
        
        changes = {
            'new_packages': [],
            'removed_packages': [],
            'updated_packages': [],
            'new_vulnerabilities': [],
            'resolved_vulnerabilities': []
        }
        
        # Compare packages
        baseline_packages = {p.name: p.version for p in self.baseline_report.packages}
        current_packages = {p.name: p.version for p in current_report.packages}
        
        # Find new and removed packages
        changes['new_packages'] = list(set(current_packages.keys()) - set(baseline_packages.keys()))
        changes['removed_packages'] = list(set(baseline_packages.keys()) - set(current_packages.keys()))
        
        # Find updated packages
        for name in set(baseline_packages.keys()) & set(current_packages.keys()):
            if baseline_packages[name] != current_packages[name]:
                changes['updated_packages'].append({
                    'name': name,
                    'old_version': baseline_packages[name],
                    'new_version': current_packages[name]
                })
        
        return changes


def get_supply_chain_scanner() -> SupplyChainScanner:
    """Get configured supply chain scanner instance"""
    return SupplyChainScanner()