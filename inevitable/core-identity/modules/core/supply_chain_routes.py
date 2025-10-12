"""
Supply Chain Security API Routes
Provides REST API endpoints for supply chain security operations
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import json
import os

from ..core.database import get_db
from ..auth.dependencies import get_current_active_user, require_mfa
from ..auth.models import User
from .supply_chain_security import (
    get_supply_chain_scanner,
    SupplyChainMonitor,
    SupplyChainReport,
    Vulnerability,
    PackageInfo,
    VulnerabilitySeverity,
    PackageRisk,
    LicenseRisk
)

router = APIRouter(prefix="/api/supply-chain", tags=["supply-chain-security"])


# Pydantic models for API
class VulnerabilityResponse(BaseModel):
    id: str
    package_name: str
    package_version: str
    severity: str
    title: str
    description: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    fixed_versions: List[str]
    published_date: Optional[datetime]
    references: List[str]


class PackageResponse(BaseModel):
    name: str
    version: str
    license: Optional[str]
    license_risk: str
    homepage: Optional[str]
    repository: Optional[str]
    author: Optional[str]
    description: Optional[str]
    risk_score: float
    risk_assessment: str
    vulnerability_count: int
    dependencies_count: int


class ScanSummary(BaseModel):
    total_packages: int
    vulnerable_packages: int
    high_risk_packages: int
    license_violations: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    risk_score: float


class ScanReportResponse(BaseModel):
    scan_timestamp: datetime
    summary: ScanSummary
    vulnerabilities: List[VulnerabilityResponse]
    packages: List[PackageResponse]
    recommendations: List[str]


class ScanRequest(BaseModel):
    requirements_file: Optional[str] = Field(None, description="Path to requirements.txt file")
    include_dev_dependencies: bool = Field(False, description="Include development dependencies")
    severity_threshold: str = Field("medium", description="Minimum severity to report")


class PackageAnalysisRequest(BaseModel):
    package_name: str = Field(..., description="Package name to analyze")
    package_version: Optional[str] = Field(None, description="Package version to analyze")


@router.get("/health", response_model=Dict[str, str])
async def health_check():
    """Health check for supply chain security service"""
    return {"status": "healthy", "service": "supply-chain-security"}


@router.post("/scan", response_model=ScanReportResponse)
@require_mfa
async def scan_dependencies(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Perform comprehensive supply chain security scan
    
    This endpoint scans all dependencies for:
    - Known security vulnerabilities
    - License compliance issues
    - Package integrity problems
    - Suspicious or malicious packages
    """
    try:
        # Initialize scanner
        scanner = get_supply_chain_scanner()
        
        # Perform scan
        report = scanner.scan_dependencies(scan_request.requirements_file)
        
        # Filter by severity threshold
        severity_map = {
            'low': VulnerabilitySeverity.LOW,
            'medium': VulnerabilitySeverity.MEDIUM,
            'high': VulnerabilitySeverity.HIGH,
            'critical': VulnerabilitySeverity.CRITICAL
        }
        
        min_severity = severity_map.get(scan_request.severity_threshold, VulnerabilitySeverity.MEDIUM)
        filtered_vulnerabilities = [
            v for v in report.vulnerabilities 
            if _get_severity_level(v.severity) >= _get_severity_level(min_severity)
        ]
        
        # Convert to response format
        vulnerabilities_response = [
            VulnerabilityResponse(
                id=v.id,
                package_name=v.package_name,
                package_version=v.package_version,
                severity=v.severity.value,
                title=v.title,
                description=v.description,
                cve_ids=v.cve_ids,
                cvss_score=v.cvss_score,
                fixed_versions=v.fixed_versions,
                published_date=v.published_date,
                references=v.references
            )
            for v in filtered_vulnerabilities
        ]
        
        packages_response = [
            PackageResponse(
                name=p.name,
                version=p.version,
                license=p.license,
                license_risk=p.license_risk.value,
                homepage=p.homepage,
                repository=p.repository,
                author=p.author,
                description=p.description,
                risk_score=p.risk_score,
                risk_assessment=p.risk_assessment.value,
                vulnerability_count=len(p.vulnerabilities),
                dependencies_count=len(p.dependencies)
            )
            for p in report.packages
        ]
        
        # Calculate summary statistics
        critical_vulns = [v for v in filtered_vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]
        high_vulns = [v for v in filtered_vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]
        
        summary = ScanSummary(
            total_packages=report.total_packages,
            vulnerable_packages=report.vulnerable_packages,
            high_risk_packages=report.high_risk_packages,
            license_violations=report.license_violations,
            total_vulnerabilities=len(filtered_vulnerabilities),
            critical_vulnerabilities=len(critical_vulns),
            high_vulnerabilities=len(high_vulns),
            risk_score=report.risk_score
        )
        
        # Schedule background audit logging
        background_tasks.add_task(
            _log_supply_chain_scan,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            scan_summary=summary
        )
        
        return ScanReportResponse(
            scan_timestamp=report.scan_timestamp,
            summary=summary,
            vulnerabilities=vulnerabilities_response,
            packages=packages_response,
            recommendations=report.recommendations
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Supply chain scan failed: {str(e)}"
        )


@router.post("/analyze", response_model=PackageResponse)
@require_mfa
async def analyze_package(
    analysis_request: PackageAnalysisRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Analyze a specific package for security issues
    
    Provides detailed security analysis for a single package including:
    - Vulnerability assessment
    - Risk scoring
    - License compliance
    - Package integrity verification
    """
    try:
        scanner = get_supply_chain_scanner()
        
        # If no version specified, try to get installed version
        package_version = analysis_request.package_version
        if not package_version:
            try:
                import pkg_resources
                dist = pkg_resources.get_distribution(analysis_request.package_name)
                package_version = dist.version
            except pkg_resources.DistributionNotFound:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Package {analysis_request.package_name} not found and no version specified"
                )
        
        # Analyze the package
        package_info = scanner._analyze_package(
            analysis_request.package_name, 
            package_version
        )
        
        return PackageResponse(
            name=package_info.name,
            version=package_info.version,
            license=package_info.license,
            license_risk=package_info.license_risk.value,
            homepage=package_info.homepage,
            repository=package_info.repository,
            author=package_info.author,
            description=package_info.description,
            risk_score=package_info.risk_score,
            risk_assessment=package_info.risk_assessment.value,
            vulnerability_count=len(package_info.vulnerabilities),
            dependencies_count=len(package_info.dependencies)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Package analysis failed: {str(e)}"
        )


@router.get("/sbom", response_model=Dict[str, Any])
@require_mfa
async def generate_sbom(
    requirements_file: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Generate Software Bill of Materials (SBOM)
    
    Creates a comprehensive SBOM in SPDX format containing:
    - All dependency information
    - License details
    - Security vulnerability references
    - Package integrity data
    """
    try:
        scanner = get_supply_chain_scanner()
        
        # Perform scan to get package information
        report = scanner.scan_dependencies(requirements_file)
        
        return report.sbom
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SBOM generation failed: {str(e)}"
        )


@router.post("/baseline")
@require_mfa
async def establish_baseline(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Establish security baseline for monitoring
    
    Creates a baseline scan that can be used to monitor for changes
    in the supply chain security posture over time.
    """
    try:
        scanner = get_supply_chain_scanner()
        monitor = SupplyChainMonitor(scanner)
        
        baseline_report = monitor.establish_baseline()
        
        # Store baseline data (in a real implementation, this would go to database)
        baseline_data = {
            'timestamp': baseline_report.scan_timestamp.isoformat(),
            'user_id': current_user.id,
            'tenant_id': current_user.tenant_id,
            'total_packages': baseline_report.total_packages,
            'vulnerable_packages': baseline_report.vulnerable_packages,
            'risk_score': baseline_report.risk_score,
            'packages': {p.name: p.version for p in baseline_report.packages}
        }
        
        return {
            "message": "Security baseline established successfully",
            "baseline_timestamp": baseline_report.scan_timestamp,
            "total_packages": baseline_report.total_packages,
            "vulnerable_packages": baseline_report.vulnerable_packages,
            "risk_score": baseline_report.risk_score
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Baseline establishment failed: {str(e)}"
        )


@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    package_name: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    List known vulnerabilities
    
    Retrieves a list of known vulnerabilities affecting the current
    dependency set, with optional filtering by severity or package.
    """
    try:
        scanner = get_supply_chain_scanner()
        report = scanner.scan_dependencies()
        
        vulnerabilities = report.vulnerabilities
        
        # Filter by severity if specified
        if severity:
            severity_filter = VulnerabilitySeverity(severity.lower())
            vulnerabilities = [v for v in vulnerabilities if v.severity == severity_filter]
        
        # Filter by package name if specified
        if package_name:
            vulnerabilities = [v for v in vulnerabilities if v.package_name == package_name]
        
        # Apply limit
        vulnerabilities = vulnerabilities[:limit]
        
        return [
            VulnerabilityResponse(
                id=v.id,
                package_name=v.package_name,
                package_version=v.package_version,
                severity=v.severity.value,
                title=v.title,
                description=v.description,
                cve_ids=v.cve_ids,
                cvss_score=v.cvss_score,
                fixed_versions=v.fixed_versions,
                published_date=v.published_date,
                references=v.references
            )
            for v in vulnerabilities
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve vulnerabilities: {str(e)}"
        )


@router.get("/packages", response_model=List[PackageResponse])
async def list_packages(
    risk_threshold: float = 5.0,
    license_risk: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    List analyzed packages
    
    Retrieves a list of analyzed packages with risk assessments,
    with optional filtering by risk score or license type.
    """
    try:
        scanner = get_supply_chain_scanner()
        report = scanner.scan_dependencies()
        
        packages = report.packages
        
        # Filter by risk threshold
        packages = [p for p in packages if p.risk_score >= risk_threshold]
        
        # Filter by license risk if specified
        if license_risk:
            license_filter = LicenseRisk(license_risk.lower())
            packages = [p for p in packages if p.license_risk == license_filter]
        
        # Sort by risk score (highest first)
        packages.sort(key=lambda p: p.risk_score, reverse=True)
        
        # Apply limit
        packages = packages[:limit]
        
        return [
            PackageResponse(
                name=p.name,
                version=p.version,
                license=p.license,
                license_risk=p.license_risk.value,
                homepage=p.homepage,
                repository=p.repository,
                author=p.author,
                description=p.description,
                risk_score=p.risk_score,
                risk_assessment=p.risk_assessment.value,
                vulnerability_count=len(p.vulnerabilities),
                dependencies_count=len(p.dependencies)
            )
            for p in packages
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve packages: {str(e)}"
        )


@router.get("/statistics", response_model=Dict[str, Any])
async def get_statistics(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get supply chain security statistics
    
    Provides an overview of the current supply chain security posture
    including risk distribution, vulnerability counts, and trends.
    """
    try:
        scanner = get_supply_chain_scanner()
        report = scanner.scan_dependencies()
        
        # Calculate statistics
        risk_distribution = {
            'trusted': len([p for p in report.packages if p.risk_assessment == PackageRisk.TRUSTED]),
            'verified': len([p for p in report.packages if p.risk_assessment == PackageRisk.VERIFIED]),
            'suspicious': len([p for p in report.packages if p.risk_assessment == PackageRisk.SUSPICIOUS]),
            'malicious': len([p for p in report.packages if p.risk_assessment == PackageRisk.MALICIOUS]),
            'unknown': len([p for p in report.packages if p.risk_assessment == PackageRisk.UNKNOWN])
        }
        
        vulnerability_distribution = {
            'critical': len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]),
            'high': len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]),
            'medium': len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM]),
            'low': len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.LOW]),
            'unknown': len([v for v in report.vulnerabilities if v.severity == VulnerabilitySeverity.UNKNOWN])
        }
        
        license_distribution = {
            'safe': len([p for p in report.packages if p.license_risk == LicenseRisk.SAFE]),
            'permissive': len([p for p in report.packages if p.license_risk == LicenseRisk.PERMISSIVE]),
            'copyleft': len([p for p in report.packages if p.license_risk == LicenseRisk.COPYLEFT]),
            'restricted': len([p for p in report.packages if p.license_risk == LicenseRisk.RESTRICTED]),
            'unknown': len([p for p in report.packages if p.license_risk == LicenseRisk.UNKNOWN])
        }
        
        # Calculate average risk score
        avg_risk_score = sum(p.risk_score for p in report.packages) / len(report.packages) if report.packages else 0
        
        return {
            'scan_timestamp': report.scan_timestamp,
            'summary': {
                'total_packages': report.total_packages,
                'vulnerable_packages': report.vulnerable_packages,
                'high_risk_packages': report.high_risk_packages,
                'license_violations': report.license_violations,
                'overall_risk_score': report.risk_score,
                'average_package_risk_score': avg_risk_score
            },
            'risk_distribution': risk_distribution,
            'vulnerability_distribution': vulnerability_distribution,
            'license_distribution': license_distribution,
            'recommendations_count': len(report.recommendations)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


# Helper functions
def _get_severity_level(severity: VulnerabilitySeverity) -> int:
    """Convert severity to numeric level for comparison"""
    levels = {
        VulnerabilitySeverity.UNKNOWN: 0,
        VulnerabilitySeverity.LOW: 1,
        VulnerabilitySeverity.MEDIUM: 2,
        VulnerabilitySeverity.HIGH: 3,
        VulnerabilitySeverity.CRITICAL: 4
    }
    return levels.get(severity, 0)


async def _log_supply_chain_scan(user_id: int, tenant_id: str, scan_summary: ScanSummary):
    """Log supply chain scan for audit purposes"""
    try:
        # In a real implementation, this would write to audit log
        import logging
        logger = logging.getLogger(__name__)
        logger.info(
            f"Supply chain scan completed",
            extra={
                'user_id': user_id,
                'tenant_id': tenant_id,
                'total_packages': scan_summary.total_packages,
                'vulnerable_packages': scan_summary.vulnerable_packages,
                'critical_vulnerabilities': scan_summary.critical_vulnerabilities,
                'risk_score': scan_summary.risk_score,
                'event_type': 'supply_chain_scan'
            }
        )
    except Exception as e:
        # Don't let logging failures affect the main operation
        pass