"""
Dependency Vulnerability Scanner API Routes for Platform Forge
Provides endpoints for dependency security scanning and reporting

Features:
- Dependency vulnerability scanning
- Security report generation
- Export functionality
- Scan scheduling and monitoring
- License compliance checking
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
import os
import tempfile
from datetime import datetime

from .database import get_db
from .deps import get_current_active_user, get_current_superuser
from ..auth.models import User
from .dependency_scanner import (
    get_dependency_scanner, 
    DependencyVulnerabilityScanner,
    VulnerabilitySeverity,
    LicenseType
)
from .validators import SecureBaseModel

router = APIRouter(prefix="/api/dependency-security", tags=["dependency-security"])


class ScanRequest(SecureBaseModel):
    """Dependency scan request"""
    requirements_files: Optional[List[str]] = Field(default=None, description="Requirements files to scan")
    include_dev: bool = Field(default=True, description="Include development dependencies")
    scan_format: str = Field(default="json", description="Report format: json, csv, html")


class VulnerabilityInfo(SecureBaseModel):
    """Vulnerability information response"""
    id: str
    package_name: str
    severity: str
    description: str
    fixed_version: Optional[str]
    cve_ids: List[str]


class PackageInfo(SecureBaseModel):
    """Package information response"""
    name: str
    version: str
    license: str
    license_type: str
    vulnerabilities: List[VulnerabilityInfo]
    is_dev_dependency: bool


class ScanSummary(SecureBaseModel):
    """Scan summary response"""
    timestamp: str
    total_packages: int
    vulnerable_packages: int
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    scan_duration: float
    recommendations: List[str]


class DetailedScanReport(SecureBaseModel):
    """Detailed scan report response"""
    summary: ScanSummary
    packages: List[PackageInfo]
    scan_errors: List[str]


@router.post("/scan", response_model=ScanSummary)
async def scan_dependencies(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_superuser),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    Perform dependency vulnerability scan (admin only)
    
    Scans project dependencies for known security vulnerabilities
    """
    try:
        # Validate requirements files if provided
        if request.requirements_files:
            for req_file in request.requirements_files:
                if not os.path.exists(req_file):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Requirements file not found: {req_file}"
                    )
        
        # Perform scan
        report = scanner.scan_dependencies(
            requirements_files=request.requirements_files,
            include_dev=request.include_dev
        )
        
        # Convert severity enum to strings for response
        severity_counts = {
            severity.value: count 
            for severity, count in report.vulnerabilities_by_severity.items()
        }
        
        summary = ScanSummary(
            timestamp=report.timestamp.isoformat(),
            total_packages=report.total_packages,
            vulnerable_packages=report.vulnerable_packages,
            total_vulnerabilities=report.total_vulnerabilities,
            vulnerabilities_by_severity=severity_counts,
            scan_duration=report.scan_duration,
            recommendations=report.recommendations
        )
        
        # Store full report for detailed endpoint
        # In production, this would be stored in database
        scanner.last_scan_report = report
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Dependency scan failed: {str(e)}"
        )


@router.get("/scan/detailed", response_model=DetailedScanReport)
async def get_detailed_scan_report(
    current_user: User = Depends(get_current_superuser),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    Get detailed dependency scan report (admin only)
    
    Returns complete scan results including all packages and vulnerabilities
    """
    try:
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            raise HTTPException(
                status_code=404,
                detail="No scan report available. Run a scan first."
            )
        
        report = scanner.last_scan_report
        
        # Convert to response format
        packages = []
        for pkg in report.packages:
            vulnerabilities = []
            for vuln in pkg.vulnerabilities:
                vulnerabilities.append(VulnerabilityInfo(
                    id=vuln.id,
                    package_name=vuln.package_name,
                    severity=vuln.severity.value,
                    description=vuln.description,
                    fixed_version=vuln.fixed_version,
                    cve_ids=vuln.cve_ids
                ))
            
            packages.append(PackageInfo(
                name=pkg.name,
                version=pkg.version,
                license=pkg.license,
                license_type=pkg.license_type.value,
                vulnerabilities=vulnerabilities,
                is_dev_dependency=pkg.is_dev_dependency
            ))
        
        # Summary
        severity_counts = {
            severity.value: count 
            for severity, count in report.vulnerabilities_by_severity.items()
        }
        
        summary = ScanSummary(
            timestamp=report.timestamp.isoformat(),
            total_packages=report.total_packages,
            vulnerable_packages=report.vulnerable_packages,
            total_vulnerabilities=report.total_vulnerabilities,
            vulnerabilities_by_severity=severity_counts,
            scan_duration=report.scan_duration,
            recommendations=report.recommendations
        )
        
        return DetailedScanReport(
            summary=summary,
            packages=packages,
            scan_errors=report.scan_errors
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve scan report: {str(e)}"
        )


@router.get("/scan/export/{format}")
async def export_scan_report(
    format: str,
    current_user: User = Depends(get_current_superuser),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    Export dependency scan report in specified format (admin only)
    
    Available formats: json, csv, html
    """
    try:
        # Validate format
        if format.lower() not in ["json", "csv", "html"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid format. Must be one of: json, csv, html"
            )
        
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            raise HTTPException(
                status_code=404,
                detail="No scan report available. Run a scan first."
            )
        
        report = scanner.last_scan_report
        
        # Export report
        exported_data = scanner.export_report(report, format.lower())
        
        # Set appropriate response headers
        if format.lower() == "json":
            media_type = "application/json"
            filename = f"dependency-scan-{report.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        elif format.lower() == "csv":
            media_type = "text/csv"
            filename = f"dependency-scan-{report.timestamp.strftime('%Y%m%d_%H%M%S')}.csv"
        else:  # html
            media_type = "text/html"
            filename = f"dependency-scan-{report.timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        return Response(
            content=exported_data,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Export failed: {str(e)}"
        )


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    package: Optional[str] = Query(None, description="Filter by package name"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    current_user: User = Depends(get_current_active_user),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    List known vulnerabilities from last scan
    
    Supports filtering by severity and package name
    """
    try:
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            return {
                "vulnerabilities": [],
                "total": 0,
                "message": "No scan data available. Run a scan first."
            }
        
        report = scanner.last_scan_report
        
        # Collect all vulnerabilities
        all_vulnerabilities = []
        for pkg in report.packages:
            for vuln in pkg.vulnerabilities:
                # Apply filters
                if severity and vuln.severity.value.lower() != severity.lower():
                    continue
                if package and package.lower() not in pkg.name.lower():
                    continue
                
                all_vulnerabilities.append({
                    "id": vuln.id,
                    "package_name": vuln.package_name,
                    "package_version": pkg.version,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "fixed_version": vuln.fixed_version,
                    "cve_ids": vuln.cve_ids,
                    "published_date": vuln.published_date.isoformat() if vuln.published_date else None
                })
        
        # Apply limit
        limited_vulnerabilities = all_vulnerabilities[:limit]
        
        return {
            "vulnerabilities": limited_vulnerabilities,
            "total": len(all_vulnerabilities),
            "returned": len(limited_vulnerabilities),
            "filters_applied": {
                "severity": severity,
                "package": package,
                "limit": limit
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list vulnerabilities: {str(e)}"
        )


@router.get("/packages")
async def list_packages(
    vulnerable_only: bool = Query(False, description="Show only vulnerable packages"),
    license_type: Optional[str] = Query(None, description="Filter by license type"),
    current_user: User = Depends(get_current_active_user),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    List analyzed packages from last scan
    
    Supports filtering by vulnerability status and license type
    """
    try:
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            return {
                "packages": [],
                "total": 0,
                "message": "No scan data available. Run a scan first."
            }
        
        report = scanner.last_scan_report
        
        # Filter packages
        filtered_packages = []
        for pkg in report.packages:
            # Apply filters
            if vulnerable_only and not pkg.vulnerabilities:
                continue
            if license_type and pkg.license_type.value.lower() != license_type.lower():
                continue
            
            filtered_packages.append({
                "name": pkg.name,
                "version": pkg.version,
                "license": pkg.license,
                "license_type": pkg.license_type.value,
                "vulnerability_count": len(pkg.vulnerabilities),
                "is_dev_dependency": pkg.is_dev_dependency,
                "dependencies": pkg.dependencies
            })
        
        return {
            "packages": filtered_packages,
            "total": len(filtered_packages),
            "filters_applied": {
                "vulnerable_only": vulnerable_only,
                "license_type": license_type
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list packages: {str(e)}"
        )


@router.get("/license-compliance")
async def check_license_compliance(
    current_user: User = Depends(get_current_active_user),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    Check license compliance for dependencies
    
    Analyzes licenses and provides compliance recommendations
    """
    try:
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            return {
                "compliance_status": "unknown",
                "message": "No scan data available. Run a scan first."
            }
        
        report = scanner.last_scan_report
        
        # Analyze licenses
        license_analysis = {
            "total_packages": len(report.packages),
            "by_license_type": {},
            "by_specific_license": {},
            "unknown_licenses": [],
            "potential_issues": []
        }
        
        for pkg in report.packages:
            # Count by license type
            license_type = pkg.license_type.value
            license_analysis["by_license_type"][license_type] = \
                license_analysis["by_license_type"].get(license_type, 0) + 1
            
            # Count by specific license
            license_analysis["by_specific_license"][pkg.license] = \
                license_analysis["by_specific_license"].get(pkg.license, 0) + 1
            
            # Track unknown licenses
            if pkg.license_type == LicenseType.UNKNOWN:
                license_analysis["unknown_licenses"].append({
                    "package": pkg.name,
                    "version": pkg.version,
                    "license": pkg.license
                })
            
            # Identify potential issues
            if pkg.license_type == LicenseType.COPYLEFT and not pkg.is_dev_dependency:
                license_analysis["potential_issues"].append({
                    "package": pkg.name,
                    "issue": "Copyleft license in production dependency",
                    "license": pkg.license,
                    "recommendation": "Review license compatibility with your project"
                })
        
        # Determine overall compliance status
        if license_analysis["potential_issues"]:
            compliance_status = "needs_review"
        elif license_analysis["unknown_licenses"]:
            compliance_status = "incomplete"
        else:
            compliance_status = "compliant"
        
        license_analysis["compliance_status"] = compliance_status
        
        return license_analysis
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"License compliance check failed: {str(e)}"
        )


@router.get("/security-metrics")
async def get_security_metrics(
    current_user: User = Depends(get_current_superuser),
    scanner: DependencyVulnerabilityScanner = Depends(get_dependency_scanner)
):
    """
    Get dependency security metrics (admin only)
    
    Provides overall security posture metrics
    """
    try:
        # Get last scan report
        if not hasattr(scanner, 'last_scan_report') or not scanner.last_scan_report:
            return {
                "metrics": {},
                "message": "No scan data available. Run a scan first."
            }
        
        report = scanner.last_scan_report
        
        # Calculate security metrics
        metrics = {
            "scan_timestamp": report.timestamp.isoformat(),
            "dependency_count": {
                "total": report.total_packages,
                "production": len([p for p in report.packages if not p.is_dev_dependency]),
                "development": len([p for p in report.packages if p.is_dev_dependency])
            },
            "vulnerability_metrics": {
                "total_vulnerabilities": report.total_vulnerabilities,
                "vulnerable_packages": report.vulnerable_packages,
                "vulnerability_density": round(
                    report.total_vulnerabilities / report.total_packages if report.total_packages > 0 else 0, 
                    2
                ),
                "by_severity": {
                    sev.value: count for sev, count in report.vulnerabilities_by_severity.items()
                }
            },
            "license_metrics": {
                "by_type": {},
                "unknown_count": 0
            },
            "security_score": 0.0,
            "recommendations_count": len(report.recommendations)
        }
        
        # Calculate license metrics
        for pkg in report.packages:
            license_type = pkg.license_type.value
            metrics["license_metrics"]["by_type"][license_type] = \
                metrics["license_metrics"]["by_type"].get(license_type, 0) + 1
            
            if pkg.license_type == LicenseType.UNKNOWN:
                metrics["license_metrics"]["unknown_count"] += 1
        
        # Calculate security score (0-100)
        score = 100.0
        
        # Deduct points for vulnerabilities
        critical_count = report.vulnerabilities_by_severity.get(VulnerabilitySeverity.CRITICAL, 0)
        high_count = report.vulnerabilities_by_severity.get(VulnerabilitySeverity.HIGH, 0)
        medium_count = report.vulnerabilities_by_severity.get(VulnerabilitySeverity.MEDIUM, 0)
        
        score -= (critical_count * 25)  # Critical: -25 points each
        score -= (high_count * 10)      # High: -10 points each
        score -= (medium_count * 5)     # Medium: -5 points each
        
        # Deduct points for unknown licenses
        score -= (metrics["license_metrics"]["unknown_count"] * 2)
        
        metrics["security_score"] = max(0.0, score)
        
        return metrics
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to calculate security metrics: {str(e)}"
        )