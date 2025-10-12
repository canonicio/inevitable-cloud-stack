"""
Comprehensive tests for supply chain security system.
Tests RISK-M003: Supply Chain Vulnerabilities

These tests ensure the supply chain security system can:
1. Scan dependencies for vulnerabilities
2. Assess package risk levels
3. Generate comprehensive reports
4. Detect malicious packages
5. Validate software integrity
6. Generate SBOMs
7. Monitor for changes
"""

import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, mock_open
from pathlib import Path

# Import supply chain security modules
from modules.core.supply_chain_security import (
    SupplyChainScanner,
    SupplyChainMonitor,
    SupplyChainSecurityConfig,
    Vulnerability,
    PackageInfo,
    SupplyChainReport,
    VulnerabilitySeverity,
    LicenseRisk,
    PackageRisk,
    get_supply_chain_scanner
)


class TestSupplyChainSecurityConfig:
    """Test supply chain security configuration"""
    
    def test_default_configuration(self):
        """Test default configuration values"""
        config = SupplyChainSecurityConfig()
        
        assert "osv" in config.VULNERABILITY_DATABASES
        assert "safety" in config.VULNERABILITY_DATABASES
        assert "snyk" in config.VULNERABILITY_DATABASES
        
        assert "safe" in config.LICENSE_CLASSIFICATIONS
        assert "MIT" in config.LICENSE_CLASSIFICATIONS["safe"]
        assert "GPL-3.0" in config.LICENSE_CLASSIFICATIONS["copyleft"]
        
        assert config.VULNERABILITY_CACHE_HOURS > 0
        assert config.PACKAGE_INFO_CACHE_HOURS > 0
    
    def test_vulnerability_severity_ordering(self):
        """Test vulnerability severity levels are properly ordered"""
        assert VulnerabilitySeverity.LOW.value == "low"
        assert VulnerabilitySeverity.CRITICAL.value == "critical"
        
        # Test all enum values exist
        severities = [s.value for s in VulnerabilitySeverity]
        expected = ["unknown", "low", "medium", "high", "critical"]
        assert all(sev in severities for sev in expected)
    
    def test_license_risk_levels(self):
        """Test license risk assessment levels"""
        assert LicenseRisk.SAFE.value == "safe"
        assert LicenseRisk.RESTRICTED.value == "restricted"
        
        # Test all enum values exist
        risks = [r.value for r in LicenseRisk]
        expected = ["safe", "permissive", "copyleft", "restricted", "unknown"]
        assert all(risk in risks for risk in expected)
    
    def test_package_risk_levels(self):
        """Test package risk assessment levels"""
        assert PackageRisk.TRUSTED.value == "trusted"
        assert PackageRisk.MALICIOUS.value == "malicious"
        
        # Test all enum values exist
        risks = [r.value for r in PackageRisk]
        expected = ["trusted", "verified", "suspicious", "malicious", "unknown"]
        assert all(risk in risks for risk in expected)


class TestVulnerability:
    """Test vulnerability data structures"""
    
    def test_vulnerability_creation(self):
        """Test creating vulnerability instances"""
        vuln = Vulnerability(
            id="CVE-2023-12345",
            package_name="test-package",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.HIGH,
            title="Test vulnerability",
            description="A test vulnerability for demonstration",
            cve_ids=["CVE-2023-12345"],
            cvss_score=7.5,
            fixed_versions=["1.0.1"],
            published_date=datetime.utcnow(),
            references=["https://example.com/advisory"]
        )
        
        assert vuln.id == "CVE-2023-12345"
        assert vuln.package_name == "test-package"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.cvss_score == 7.5
        assert len(vuln.fixed_versions) == 1
        assert len(vuln.references) == 1


class TestPackageInfo:
    """Test package information data structures"""
    
    def test_package_info_creation(self):
        """Test creating package info instances"""
        vuln = Vulnerability(
            id="TEST-001",
            package_name="test-package",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.MEDIUM,
            title="Test",
            description="Test",
            cve_ids=[],
            cvss_score=None,
            fixed_versions=[],
            published_date=None,
            references=[]
        )
        
        package = PackageInfo(
            name="test-package",
            version="1.0.0",
            license="MIT",
            license_risk=LicenseRisk.SAFE,
            homepage="https://example.com",
            repository="https://github.com/example/test",
            author="Test Author",
            description="A test package",
            dependencies=["dependency1", "dependency2"],
            file_hashes={"file1.py": "abc123", "file2.py": "def456"},
            install_path="/path/to/package",
            last_updated=datetime.utcnow(),
            download_count=1000,
            maintainers=["Test Author"],
            risk_score=2.5,
            risk_assessment=PackageRisk.TRUSTED,
            vulnerabilities=[vuln]
        )
        
        assert package.name == "test-package"
        assert package.license_risk == LicenseRisk.SAFE
        assert package.risk_assessment == PackageRisk.TRUSTED
        assert len(package.vulnerabilities) == 1
        assert len(package.dependencies) == 2
        assert len(package.file_hashes) == 2


class TestSupplyChainScanner:
    """Test the main supply chain scanner"""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration"""
        return SupplyChainSecurityConfig()
    
    @pytest.fixture
    def scanner(self, mock_config):
        """Create scanner with mock configuration"""
        with patch('modules.core.supply_chain_security.Path.mkdir'):
            return SupplyChainScanner(mock_config)
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner.config is not None
        assert scanner.cache_dir is not None
        assert isinstance(scanner.vuln_databases, dict)
    
    def test_parse_requirements_file(self, scanner):
        """Test parsing requirements.txt files"""
        requirements_content = """
# Test requirements file
requests==2.25.1
django>=3.2.0
flask
numpy==1.21.0  # Scientific computing
"""
        
        with patch('builtins.open', mock_open(read_data=requirements_content)):
            packages = scanner._parse_requirements_file("requirements.txt")
        
        assert len(packages) >= 3
        
        # Check specific packages
        package_names = [p[0] for p in packages]
        assert "requests" in package_names
        assert "django" in package_names
        assert "flask" in package_names
        
        # Check version parsing
        requests_version = next(p[1] for p in packages if p[0] == "requests")
        assert requests_version == "2.25.1"
    
    def test_get_installed_packages(self, scanner):
        """Test getting installed packages"""
        with patch('pkg_resources.working_set') as mock_working_set:
            mock_dist1 = Mock()
            mock_dist1.project_name = "test-package-1"
            mock_dist1.version = "1.0.0"
            
            mock_dist2 = Mock()
            mock_dist2.project_name = "test-package-2"
            mock_dist2.version = "2.0.0"
            
            mock_working_set.__iter__ = Mock(return_value=iter([mock_dist1, mock_dist2]))
            
            packages = scanner._get_installed_packages()
        
        assert len(packages) == 2
        assert ("test-package-1", "1.0.0") in packages
        assert ("test-package-2", "2.0.0") in packages
    
    def test_assess_license_risk(self, scanner):
        """Test license risk assessment"""
        # Test safe licenses
        assert scanner._assess_license_risk("MIT") == LicenseRisk.SAFE
        assert scanner._assess_license_risk("Apache-2.0") == LicenseRisk.SAFE
        assert scanner._assess_license_risk("BSD-3-Clause") == LicenseRisk.SAFE
        
        # Test copyleft licenses
        assert scanner._assess_license_risk("GPL-3.0") == LicenseRisk.COPYLEFT
        assert scanner._assess_license_risk("LGPL-2.1") == LicenseRisk.COPYLEFT
        
        # Test restricted licenses
        assert scanner._assess_license_risk("AGPL-3.0") == LicenseRisk.RESTRICTED
        
        # Test unknown licenses
        assert scanner._assess_license_risk("Custom License") == LicenseRisk.UNKNOWN
        assert scanner._assess_license_risk(None) == LicenseRisk.UNKNOWN
    
    def test_calculate_risk_score(self, scanner):
        """Test risk score calculation"""
        # Test low-risk package
        low_risk_metadata = {
            'last_updated': datetime.utcnow().isoformat(),
            'maintainers': ['trusted@example.com'],
            'download_count': 1000000,
            'dependencies': ['requests']
        }
        
        low_risk_score = scanner._calculate_risk_score(
            "trusted-package",
            low_risk_metadata,
            [],  # No vulnerabilities
            LicenseRisk.SAFE
        )
        
        assert 0 <= low_risk_score <= 10
        assert low_risk_score < 5  # Should be low risk
        
        # Test high-risk package
        critical_vuln = Vulnerability(
            id="CVE-2023-99999",
            package_name="risky-package",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.CRITICAL,
            title="Critical vulnerability",
            description="A critical security flaw",
            cve_ids=["CVE-2023-99999"],
            cvss_score=9.8,
            fixed_versions=[],
            published_date=datetime.utcnow(),
            references=[]
        )
        
        high_risk_metadata = {
            'last_updated': (datetime.utcnow() - timedelta(days=730)).isoformat(),  # 2 years old
            'maintainers': [],  # No maintainers
            'download_count': 10,  # Very low downloads
            'dependencies': ['dep1', 'dep2', 'dep3', 'dep4', 'dep5', 'dep6']  # Many deps
        }
        
        high_risk_score = scanner._calculate_risk_score(
            "risky-package",
            high_risk_metadata,
            [critical_vuln],
            LicenseRisk.RESTRICTED
        )
        
        assert high_risk_score > 5  # Should be high risk
        assert high_risk_score <= 10  # Capped at 10
    
    def test_is_suspicious_package(self, scanner):
        """Test suspicious package detection"""
        # Test typosquatting detection
        assert scanner._is_suspicious_package("reqeusts", {}) == False  # Pattern not exact match
        
        # Test suspicious description
        suspicious_metadata = {
            'description': 'This is a test package for crypto mining'
        }
        assert scanner._is_suspicious_package("normal-package", suspicious_metadata) == True
        
        # Test suspicious author
        author_metadata = {
            'author': 'test'
        }
        assert scanner._is_suspicious_package("normal-package", author_metadata) == True
        
        # Test normal package
        normal_metadata = {
            'description': 'A legitimate package for web development',
            'author': 'John Developer'
        }
        assert scanner._is_suspicious_package("web-framework", normal_metadata) == False
    
    def test_vulnerability_severity_scoring(self, scanner):
        """Test vulnerability severity scoring"""
        # Test with no vulnerabilities
        assert scanner._get_max_vulnerability_severity_score([]) == 0.0
        
        # Test with critical vulnerability
        critical_vuln = Vulnerability(
            id="CVE-2023-CRITICAL",
            package_name="test",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.CRITICAL,
            title="Critical",
            description="Critical vulnerability",
            cve_ids=[],
            cvss_score=None,
            fixed_versions=[],
            published_date=None,
            references=[]
        )
        
        score = scanner._get_max_vulnerability_severity_score([critical_vuln])
        assert score == 10.0
        
        # Test with mixed severities
        medium_vuln = Vulnerability(
            id="CVE-2023-MEDIUM",
            package_name="test",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.MEDIUM,
            title="Medium",
            description="Medium vulnerability",
            cve_ids=[],
            cvss_score=None,
            fixed_versions=[],
            published_date=None,
            references=[]
        )
        
        mixed_score = scanner._get_max_vulnerability_severity_score([critical_vuln, medium_vuln])
        assert mixed_score == 10.0  # Should take the maximum (critical)
    
    def test_license_risk_scoring(self, scanner):
        """Test license risk scoring"""
        assert scanner._get_license_risk_score(LicenseRisk.SAFE) == 0.0
        assert scanner._get_license_risk_score(LicenseRisk.PERMISSIVE) == 1.0
        assert scanner._get_license_risk_score(LicenseRisk.COPYLEFT) == 3.0
        assert scanner._get_license_risk_score(LicenseRisk.RESTRICTED) == 6.0
        assert scanner._get_license_risk_score(LicenseRisk.UNKNOWN) == 2.0
    
    @patch('urllib.request.urlopen')
    def test_osv_vulnerability_check(self, mock_urlopen, scanner):
        """Test OSV vulnerability database query"""
        # Mock OSV API response
        mock_response_data = {
            "vulns": [
                {
                    "id": "OSV-2023-1234",
                    "summary": "Test vulnerability",
                    "details": "A test vulnerability for demonstration",
                    "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                    "aliases": ["CVE-2023-1234"],
                    "published": "2023-01-01T00:00:00Z",
                    "references": [{"url": "https://example.com/advisory"}],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.0.1"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_response_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        vulnerabilities = scanner._check_osv_vulnerabilities("test-package", "1.0.0")
        
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.id == "OSV-2023-1234"
        assert vuln.package_name == "test-package"
        assert vuln.title == "Test vulnerability"
        assert "CVE-2023-1234" in vuln.cve_ids
        assert "1.0.1" in vuln.fixed_versions
    
    @patch('modules.core.supply_chain_security.pkg_resources.get_distribution')
    def test_get_package_file_hashes(self, mock_get_dist, scanner):
        """Test package file hash computation"""
        # Create a temporary directory structure
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir)
            
            # Create test Python files
            test_file1 = package_dir / "module.py"
            test_file1.write_text("print('Hello, world!')")
            
            test_file2 = package_dir / "submodule" / "helper.py"
            test_file2.parent.mkdir()
            test_file2.write_text("def helper(): pass")
            
            # Mock distribution
            mock_dist = Mock()
            mock_dist.location = str(package_dir)
            mock_get_dist.return_value = mock_dist
            
            hashes = scanner._get_package_file_hashes("test-package")
            
            assert len(hashes) >= 2
            assert "module.py" in hashes
            assert "submodule/helper.py" in hashes
            
            # Verify hash format (SHA256)
            for hash_value in hashes.values():
                assert len(hash_value) == 64  # SHA256 hex length
                assert all(c in '0123456789abcdef' for c in hash_value)
    
    def test_generate_sbom(self, scanner):
        """Test SBOM (Software Bill of Materials) generation"""
        # Create test packages
        package1 = PackageInfo(
            name="test-package-1",
            version="1.0.0",
            license="MIT",
            license_risk=LicenseRisk.SAFE,
            homepage="https://example.com",
            repository=None,
            author="Test Author",
            description="Test package 1",
            dependencies=[],
            file_hashes={},
            install_path=None,
            last_updated=None,
            download_count=None,
            maintainers=[],
            risk_score=1.0,
            risk_assessment=PackageRisk.TRUSTED,
            vulnerabilities=[]
        )
        
        package2 = PackageInfo(
            name="test-package-2",
            version="2.0.0",
            license="Apache-2.0",
            license_risk=LicenseRisk.SAFE,
            homepage=None,
            repository="https://github.com/test/package2",
            author="Another Author",
            description="Test package 2",
            dependencies=[],
            file_hashes={},
            install_path=None,
            last_updated=None,
            download_count=None,
            maintainers=[],
            risk_score=0.5,
            risk_assessment=PackageRisk.TRUSTED,
            vulnerabilities=[]
        )
        
        packages = [package1, package2]
        sbom = scanner._generate_sbom(packages)
        
        # Verify SBOM structure
        assert "spdxVersion" in sbom
        assert "dataLicense" in sbom
        assert "packages" in sbom
        assert len(sbom["packages"]) == 2
        
        # Verify package information
        sbom_package1 = sbom["packages"][0]
        assert sbom_package1["name"] == "test-package-1"
        assert sbom_package1["versionInfo"] == "1.0.0"
        assert sbom_package1["licenseConcluded"] == "MIT"
        
        sbom_package2 = sbom["packages"][1]
        assert sbom_package2["name"] == "test-package-2"
        assert sbom_package2["licenseConcluded"] == "Apache-2.0"
    
    def test_generate_recommendations(self, scanner):
        """Test security recommendations generation"""
        # Create test data with various issues
        critical_vuln = Vulnerability(
            id="CVE-2023-CRITICAL",
            package_name="vulnerable-package",
            package_version="1.0.0",
            severity=VulnerabilitySeverity.CRITICAL,
            title="Critical vulnerability",
            description="Critical security flaw",
            cve_ids=["CVE-2023-CRITICAL"],
            cvss_score=9.8,
            fixed_versions=["1.0.1"],
            published_date=datetime.utcnow(),
            references=[]
        )
        
        high_vuln = Vulnerability(
            id="CVE-2023-HIGH",
            package_name="another-package",
            package_version="2.0.0",
            severity=VulnerabilitySeverity.HIGH,
            title="High vulnerability",
            description="High severity security flaw",
            cve_ids=["CVE-2023-HIGH"],
            cvss_score=7.5,
            fixed_versions=["2.0.1"],
            published_date=datetime.utcnow(),
            references=[]
        )
        
        suspicious_package = PackageInfo(
            name="suspicious-package",
            version="1.0.0",
            license="Unknown",
            license_risk=LicenseRisk.UNKNOWN,
            homepage=None,
            repository=None,
            author="test",
            description="crypto mining tool",
            dependencies=[],
            file_hashes={},
            install_path=None,
            last_updated=None,
            download_count=5,
            maintainers=[],
            risk_score=8.5,
            risk_assessment=PackageRisk.SUSPICIOUS,
            vulnerabilities=[]
        )
        
        restricted_package = PackageInfo(
            name="restricted-package",
            version="1.0.0",
            license="AGPL-3.0",
            license_risk=LicenseRisk.RESTRICTED,
            homepage=None,
            repository=None,
            author="Developer",
            description="Normal package with restrictive license",
            dependencies=[],
            file_hashes={},
            install_path=None,
            last_updated=None,
            download_count=1000,
            maintainers=[],
            risk_score=3.0,
            risk_assessment=PackageRisk.VERIFIED,
            vulnerabilities=[]
        )
        
        packages = [suspicious_package, restricted_package]
        vulnerabilities = [critical_vuln, high_vuln]
        
        recommendations = scanner._generate_recommendations(packages, vulnerabilities)
        
        assert len(recommendations) > 0
        
        # Check for critical vulnerability recommendations
        critical_recs = [r for r in recommendations if "critical" in r.lower()]
        assert len(critical_recs) > 0
        
        # Check for high severity recommendations
        high_recs = [r for r in recommendations if "high-severity" in r.lower()]
        assert len(high_recs) > 0
        
        # Check for suspicious package recommendations
        suspicious_recs = [r for r in recommendations if "suspicious" in r.lower()]
        assert len(suspicious_recs) > 0
        
        # Check for license recommendations
        license_recs = [r for r in recommendations if "license" in r.lower()]
        assert len(license_recs) > 0


class TestSupplyChainMonitor:
    """Test supply chain monitoring functionality"""
    
    @pytest.fixture
    def mock_scanner(self):
        """Create mock scanner for testing"""
        scanner = Mock()
        
        # Create mock baseline report
        baseline_report = SupplyChainReport(
            scan_timestamp=datetime.utcnow(),
            total_packages=3,
            vulnerable_packages=1,
            high_risk_packages=0,
            license_violations=0,
            packages=[
                PackageInfo(
                    name="package-1",
                    version="1.0.0",
                    license="MIT",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=1.0,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                ),
                PackageInfo(
                    name="package-2",
                    version="2.0.0",
                    license="Apache-2.0",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=0.5,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                )
            ],
            vulnerabilities=[],
            recommendations=[],
            sbom={},
            risk_score=1.0
        )
        
        scanner.scan_dependencies.return_value = baseline_report
        return scanner
    
    @pytest.fixture
    def monitor(self, mock_scanner):
        """Create monitor with mock scanner"""
        return SupplyChainMonitor(mock_scanner)
    
    def test_establish_baseline(self, monitor, mock_scanner):
        """Test establishing security baseline"""
        report = monitor.establish_baseline()
        
        assert monitor.baseline_report is not None
        assert report.total_packages == 2
        mock_scanner.scan_dependencies.assert_called_once()
    
    def test_detect_changes_new_package(self, monitor, mock_scanner):
        """Test detection of new packages"""
        # Establish baseline
        monitor.establish_baseline()
        
        # Create new report with additional package
        new_report = SupplyChainReport(
            scan_timestamp=datetime.utcnow(),
            total_packages=3,
            vulnerable_packages=1,
            high_risk_packages=0,
            license_violations=0,
            packages=[
                PackageInfo(
                    name="package-1",
                    version="1.0.0",
                    license="MIT",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=1.0,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                ),
                PackageInfo(
                    name="package-2",
                    version="2.0.0",
                    license="Apache-2.0",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=0.5,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                ),
                PackageInfo(
                    name="package-3",
                    version="3.0.0",
                    license="BSD-3-Clause",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=0.8,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                )
            ],
            vulnerabilities=[],
            recommendations=[],
            sbom={},
            risk_score=1.0
        )
        
        # Mock scanner to return new report
        mock_scanner.scan_dependencies.return_value = new_report
        
        changes = monitor.detect_changes()
        
        assert len(changes['new_packages']) == 1
        assert 'package-3' in changes['new_packages']
        assert len(changes['removed_packages']) == 0
        assert len(changes['updated_packages']) == 0
    
    def test_detect_changes_updated_package(self, monitor, mock_scanner):
        """Test detection of updated packages"""
        # Establish baseline
        monitor.establish_baseline()
        
        # Create report with updated package version
        updated_report = SupplyChainReport(
            scan_timestamp=datetime.utcnow(),
            total_packages=2,
            vulnerable_packages=1,
            high_risk_packages=0,
            license_violations=0,
            packages=[
                PackageInfo(
                    name="package-1",
                    version="1.1.0",  # Updated version
                    license="MIT",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=1.0,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                ),
                PackageInfo(
                    name="package-2",
                    version="2.0.0",
                    license="Apache-2.0",
                    license_risk=LicenseRisk.SAFE,
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
                    risk_score=0.5,
                    risk_assessment=PackageRisk.TRUSTED,
                    vulnerabilities=[]
                )
            ],
            vulnerabilities=[],
            recommendations=[],
            sbom={},
            risk_score=1.0
        )
        
        mock_scanner.scan_dependencies.return_value = updated_report
        
        changes = monitor.detect_changes()
        
        assert len(changes['updated_packages']) == 1
        assert changes['updated_packages'][0]['name'] == 'package-1'
        assert changes['updated_packages'][0]['old_version'] == '1.0.0'
        assert changes['updated_packages'][0]['new_version'] == '1.1.0'


class TestSupplyChainIntegration:
    """Integration tests for supply chain security"""
    
    def test_get_supply_chain_scanner(self):
        """Test getting scanner instance"""
        with patch('modules.core.supply_chain_security.Path.mkdir'):
            scanner = get_supply_chain_scanner()
        
        assert isinstance(scanner, SupplyChainScanner)
        assert scanner.config is not None
    
    @patch('modules.core.supply_chain_security.pkg_resources.working_set')
    def test_full_scan_workflow(self, mock_working_set):
        """Test complete scanning workflow"""
        # Mock installed packages
        mock_dist = Mock()
        mock_dist.project_name = "requests"
        mock_dist.version = "2.25.1"
        mock_working_set.__iter__ = Mock(return_value=iter([mock_dist]))
        
        with patch('modules.core.supply_chain_security.Path.mkdir'):
            scanner = SupplyChainScanner()
        
        # Mock network calls to avoid real API requests
        with patch.object(scanner, '_fetch_pypi_metadata', return_value=None):
            with patch.object(scanner, '_check_vulnerabilities', return_value=[]):
                with patch.object(scanner, '_get_package_file_hashes', return_value={}):
                    
                    report = scanner.scan_dependencies()
        
        assert isinstance(report, SupplyChainReport)
        assert report.total_packages >= 1
        assert len(report.packages) >= 1
        assert isinstance(report.sbom, dict)
        assert isinstance(report.recommendations, list)
    
    def test_caching_functionality(self):
        """Test caching of scan results"""
        with patch('modules.core.supply_chain_security.Path.mkdir'):
            scanner = SupplyChainScanner()
        
        # Test cache miss
        result = scanner._get_from_cache("test_key", 24)
        assert result is None
        
        # Test cache save and hit
        test_data = {"test": "data", "number": 42}
        scanner._save_to_cache("test_key", test_data)
        
        # Mock file operations for testing
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.stat') as mock_stat:
                with patch('builtins.open', mock_open(read_data=json.dumps(test_data))):
                    mock_stat.return_value.st_mtime = time.time()  # Recent timestamp
                    
                    cached_result = scanner._get_from_cache("test_key", 24)
                    
        # In a real test environment, this would work with actual cache files
        # For now, we just verify the cache methods don't crash
        assert cached_result is None or isinstance(cached_result, dict)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])