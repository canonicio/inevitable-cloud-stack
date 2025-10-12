"""
Supply Chain Security CLI Commands
Provides command-line interface for supply chain security operations
"""

import click
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

from .supply_chain_security import (
    get_supply_chain_scanner,
    SupplyChainMonitor,
    VulnerabilitySeverity,
    PackageRisk,
    LicenseRisk
)


@click.group()
def supply_chain():
    """Supply chain security management commands"""
    pass


@supply_chain.command()
@click.option('--requirements', '-r', type=click.Path(exists=True), 
              help='Path to requirements.txt file')
@click.option('--output', '-o', type=click.Path(), 
              help='Output file for scan results (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['json', 'table', 'sbom']), 
              default='table', help='Output format')
@click.option('--severity-threshold', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              default='medium', help='Minimum severity to report')
@click.option('--fail-on-critical', is_flag=True, 
              help='Exit with non-zero code if critical vulnerabilities found')
def scan(requirements: Optional[str], output: Optional[str], output_format: str, 
         severity_threshold: str, fail_on_critical: bool):
    """Scan dependencies for security vulnerabilities"""
    
    click.echo("🔒 Starting Platform Forge Supply Chain Security Scan")
    click.echo("=" * 60)
    
    try:
        # Initialize scanner
        scanner = get_supply_chain_scanner()
        
        # Perform scan
        with click.progressbar(length=100, label='Scanning dependencies') as bar:
            report = scanner.scan_dependencies(requirements)
            bar.update(100)
        
        # Filter results by severity threshold
        severity_map = {
            'low': VulnerabilitySeverity.LOW,
            'medium': VulnerabilitySeverity.MEDIUM,
            'high': VulnerabilitySeverity.HIGH,
            'critical': VulnerabilitySeverity.CRITICAL
        }
        
        min_severity = severity_map[severity_threshold]
        filtered_vulnerabilities = [
            v for v in report.vulnerabilities 
            if _severity_level(v.severity) >= _severity_level(min_severity)
        ]
        
        # Output results
        if output_format == 'json':
            output_json(report, output, filtered_vulnerabilities)
        elif output_format == 'sbom':
            output_sbom(report, output)
        else:
            output_table(report, filtered_vulnerabilities)
        
        # Check for critical vulnerabilities
        critical_vulns = [
            v for v in filtered_vulnerabilities 
            if v.severity == VulnerabilitySeverity.CRITICAL
        ]
        
        if fail_on_critical and critical_vulns:
            click.echo(f"\n❌ Found {len(critical_vulns)} critical vulnerabilities. Exiting with error code.")
            sys.exit(1)
        
        if filtered_vulnerabilities:
            click.echo(f"\n⚠️  Scan completed with {len(filtered_vulnerabilities)} security issues found.")
        else:
            click.echo("\n✅ Scan completed successfully. No security issues found above threshold.")
            
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)


@supply_chain.command()
@click.option('--baseline-file', type=click.Path(), 
              help='File to store baseline scan results')
def baseline(baseline_file: Optional[str]):
    """Establish security baseline for monitoring"""
    
    click.echo("📊 Establishing Supply Chain Security Baseline")
    click.echo("=" * 50)
    
    try:
        scanner = get_supply_chain_scanner()
        monitor = SupplyChainMonitor(scanner)
        
        with click.progressbar(length=100, label='Scanning current state') as bar:
            baseline_report = monitor.establish_baseline()
            bar.update(100)
        
        # Save baseline if file specified
        if baseline_file:
            baseline_data = {
                'timestamp': baseline_report.scan_timestamp.isoformat(),
                'packages': {p.name: p.version for p in baseline_report.packages},
                'vulnerabilities': [
                    {
                        'id': v.id,
                        'package': v.package_name,
                        'severity': v.severity.value
                    }
                    for v in baseline_report.vulnerabilities
                ]
            }
            
            with open(baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            click.echo(f"✅ Baseline saved to {baseline_file}")
        
        click.echo(f"✅ Baseline established with {baseline_report.total_packages} packages")
        click.echo(f"📊 Current vulnerabilities: {baseline_report.vulnerable_packages}")
        click.echo(f"⚠️  High-risk packages: {baseline_report.high_risk_packages}")
        
    except Exception as e:
        click.echo(f"❌ Baseline establishment failed: {e}", err=True)
        sys.exit(1)


@supply_chain.command()
@click.option('--baseline-file', type=click.Path(exists=True), required=True,
              help='Baseline file to compare against')
def monitor(baseline_file: str):
    """Monitor for changes in supply chain since baseline"""
    
    click.echo("👁  Monitoring Supply Chain Changes")
    click.echo("=" * 40)
    
    try:
        # Load baseline
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
        
        # Current scan
        scanner = get_supply_chain_scanner()
        current_report = scanner.scan_dependencies()
        
        # Compare with baseline
        baseline_packages = baseline_data['packages']
        current_packages = {p.name: p.version for p in current_report.packages}
        
        # Find changes
        new_packages = set(current_packages.keys()) - set(baseline_packages.keys())
        removed_packages = set(baseline_packages.keys()) - set(current_packages.keys())
        updated_packages = []
        
        for name in set(baseline_packages.keys()) & set(current_packages.keys()):
            if baseline_packages[name] != current_packages[name]:
                updated_packages.append({
                    'name': name,
                    'old_version': baseline_packages[name],
                    'new_version': current_packages[name]
                })
        
        # Report changes
        if new_packages:
            click.echo(f"➕ New packages ({len(new_packages)}):")
            for pkg in sorted(new_packages):
                click.echo(f"   • {pkg} ({current_packages[pkg]})")
        
        if removed_packages:
            click.echo(f"➖ Removed packages ({len(removed_packages)}):")
            for pkg in sorted(removed_packages):
                click.echo(f"   • {pkg} ({baseline_packages[pkg]})")
        
        if updated_packages:
            click.echo(f"🔄 Updated packages ({len(updated_packages)}):")
            for pkg in updated_packages:
                click.echo(f"   • {pkg['name']}: {pkg['old_version']} → {pkg['new_version']}")
        
        if not (new_packages or removed_packages or updated_packages):
            click.echo("✅ No changes detected since baseline")
        
        # Check for new vulnerabilities
        baseline_vulns = set(v['id'] for v in baseline_data['vulnerabilities'])
        current_vulns = set(v.id for v in current_report.vulnerabilities)
        
        new_vulns = current_vulns - baseline_vulns
        resolved_vulns = baseline_vulns - current_vulns
        
        if new_vulns:
            click.echo(f"🚨 New vulnerabilities found: {len(new_vulns)}")
        
        if resolved_vulns:
            click.echo(f"✅ Vulnerabilities resolved: {len(resolved_vulns)}")
        
    except Exception as e:
        click.echo(f"❌ Monitoring failed: {e}", err=True)
        sys.exit(1)


@supply_chain.command()
@click.argument('package_name')
@click.option('--version', help='Specific package version to analyze')
def analyze(package_name: str, version: Optional[str]):
    """Analyze a specific package for security issues"""
    
    click.echo(f"🔍 Analyzing package: {package_name}")
    if version:
        click.echo(f"📦 Version: {version}")
    click.echo("=" * 40)
    
    try:
        scanner = get_supply_chain_scanner()
        
        # If no version specified, try to get installed version
        if not version:
            import pkg_resources
            try:
                dist = pkg_resources.get_distribution(package_name)
                version = dist.version
                click.echo(f"📦 Using installed version: {version}")
            except pkg_resources.DistributionNotFound:
                click.echo("❌ Package not found and no version specified")
                sys.exit(1)
        
        # Analyze the package
        package_info = scanner._analyze_package(package_name, version)
        
        # Display results
        click.echo(f"\n📊 Package Information:")
        click.echo(f"   Name: {package_info.name}")
        click.echo(f"   Version: {package_info.version}")
        click.echo(f"   License: {package_info.license or 'Unknown'}")
        click.echo(f"   License Risk: {package_info.license_risk.value}")
        click.echo(f"   Risk Score: {package_info.risk_score:.1f}/10")
        click.echo(f"   Risk Assessment: {package_info.risk_assessment.value}")
        
        if package_info.homepage:
            click.echo(f"   Homepage: {package_info.homepage}")
        
        if package_info.repository:
            click.echo(f"   Repository: {package_info.repository}")
        
        if package_info.vulnerabilities:
            click.echo(f"\n🚨 Vulnerabilities ({len(package_info.vulnerabilities)}):")
            for vuln in package_info.vulnerabilities:
                severity_color = {
                    VulnerabilitySeverity.CRITICAL: 'red',
                    VulnerabilitySeverity.HIGH: 'yellow',
                    VulnerabilitySeverity.MEDIUM: 'blue',
                    VulnerabilitySeverity.LOW: 'green'
                }.get(vuln.severity, 'white')
                
                click.echo(f"   • {vuln.id}", color=severity_color)
                click.echo(f"     Severity: {vuln.severity.value.upper()}")
                click.echo(f"     Title: {vuln.title}")
                if vuln.fixed_versions:
                    click.echo(f"     Fixed in: {', '.join(vuln.fixed_versions)}")
        else:
            click.echo("\n✅ No known vulnerabilities found")
        
        if package_info.dependencies:
            click.echo(f"\n📦 Dependencies ({len(package_info.dependencies)}):")
            for dep in package_info.dependencies[:10]:  # Show first 10
                click.echo(f"   • {dep}")
            if len(package_info.dependencies) > 10:
                click.echo(f"   ... and {len(package_info.dependencies) - 10} more")
        
    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}", err=True)
        sys.exit(1)


@supply_chain.command()
@click.option('--output', '-o', type=click.Path(), required=True,
              help='Output file for SBOM')
@click.option('--format', 'sbom_format', type=click.Choice(['spdx', 'cyclonedx']), 
              default='spdx', help='SBOM format')
def sbom(output: str, sbom_format: str):
    """Generate Software Bill of Materials (SBOM)"""
    
    click.echo("📋 Generating Software Bill of Materials")
    click.echo("=" * 45)
    
    try:
        scanner = get_supply_chain_scanner()
        
        with click.progressbar(length=100, label='Scanning dependencies') as bar:
            report = scanner.scan_dependencies()
            bar.update(100)
        
        if sbom_format == 'spdx':
            sbom_data = report.sbom
        else:
            # Could implement CycloneDX format here
            click.echo("❌ CycloneDX format not yet supported")
            sys.exit(1)
        
        # Write SBOM to file
        with open(output, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        
        click.echo(f"✅ SBOM generated: {output}")
        click.echo(f"📊 Packages documented: {len(sbom_data.get('packages', []))}")
        
    except Exception as e:
        click.echo(f"❌ SBOM generation failed: {e}", err=True)
        sys.exit(1)


def output_json(report, output_file: Optional[str], vulnerabilities):
    """Output scan results in JSON format"""
    result = {
        'scan_timestamp': report.scan_timestamp.isoformat(),
        'summary': {
            'total_packages': report.total_packages,
            'vulnerable_packages': report.vulnerable_packages,
            'high_risk_packages': report.high_risk_packages,
            'license_violations': report.license_violations,
            'risk_score': report.risk_score
        },
        'vulnerabilities': [
            {
                'id': v.id,
                'package_name': v.package_name,
                'package_version': v.package_version,
                'severity': v.severity.value,
                'title': v.title,
                'description': v.description,
                'cve_ids': v.cve_ids,
                'cvss_score': v.cvss_score,
                'fixed_versions': v.fixed_versions,
                'references': v.references
            }
            for v in vulnerabilities
        ],
        'packages': [
            {
                'name': p.name,
                'version': p.version,
                'license': p.license,
                'license_risk': p.license_risk.value,
                'risk_score': p.risk_score,
                'risk_assessment': p.risk_assessment.value,
                'vulnerability_count': len(p.vulnerabilities)
            }
            for p in report.packages
        ],
        'recommendations': report.recommendations
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        click.echo(f"✅ Results saved to {output_file}")
    else:
        click.echo(json.dumps(result, indent=2))


def output_sbom(report, output_file: Optional[str]):
    """Output SBOM"""
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report.sbom, f, indent=2)
        click.echo(f"✅ SBOM saved to {output_file}")
    else:
        click.echo(json.dumps(report.sbom, indent=2))


def output_table(report, vulnerabilities):
    """Output scan results in table format"""
    
    # Summary
    click.echo("\n📊 SCAN SUMMARY")
    click.echo("=" * 20)
    click.echo(f"Total packages scanned: {report.total_packages}")
    click.echo(f"Packages with vulnerabilities: {report.vulnerable_packages}")
    click.echo(f"High-risk packages: {report.high_risk_packages}")
    click.echo(f"License violations: {report.license_violations}")
    click.echo(f"Overall risk score: {report.risk_score:.1f}/10")
    
    # Vulnerabilities
    if vulnerabilities:
        click.echo(f"\n🚨 VULNERABILITIES ({len(vulnerabilities)})")
        click.echo("=" * 30)
        
        # Group by severity
        by_severity = {}
        for v in vulnerabilities:
            severity = v.severity.value.upper()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(v)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            if severity in by_severity:
                vulns = by_severity[severity]
                click.echo(f"\n{severity} ({len(vulns)} vulnerabilities):")
                
                for v in vulns[:5]:  # Show first 5 per severity
                    click.echo(f"  • {v.id}: {v.package_name} {v.package_version}")
                    click.echo(f"    {v.title}")
                    if v.fixed_versions:
                        click.echo(f"    Fixed in: {', '.join(v.fixed_versions)}")
                
                if len(vulns) > 5:
                    click.echo(f"    ... and {len(vulns) - 5} more {severity} vulnerabilities")
    
    # High-risk packages
    high_risk_packages = [p for p in report.packages if p.risk_score >= 7.0]
    if high_risk_packages:
        click.echo(f"\n⚠️  HIGH-RISK PACKAGES ({len(high_risk_packages)})")
        click.echo("=" * 35)
        for p in high_risk_packages:
            click.echo(f"  • {p.name} {p.version} (Risk: {p.risk_score:.1f}/10)")
            click.echo(f"    Assessment: {p.risk_assessment.value}")
            if p.vulnerabilities:
                click.echo(f"    Vulnerabilities: {len(p.vulnerabilities)}")
    
    # Recommendations
    if report.recommendations:
        click.echo(f"\n💡 RECOMMENDATIONS")
        click.echo("=" * 20)
        for i, rec in enumerate(report.recommendations[:10], 1):
            click.echo(f"  {i}. {rec}")


def _severity_level(severity: VulnerabilitySeverity) -> int:
    """Convert severity to numeric level for comparison"""
    levels = {
        VulnerabilitySeverity.UNKNOWN: 0,
        VulnerabilitySeverity.LOW: 1,
        VulnerabilitySeverity.MEDIUM: 2,
        VulnerabilitySeverity.HIGH: 3,
        VulnerabilitySeverity.CRITICAL: 4
    }
    return levels.get(severity, 0)


if __name__ == '__main__':
    supply_chain()