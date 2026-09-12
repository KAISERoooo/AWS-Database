import json
import sys
import os
from dataclasses import asdict

# Allow `database.*` imports when running with PYTHONPATH=scanner:project_root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.ec2_analyzer import EC2Analyzer
from analyzers.iam_analyzer import IAMAnalyzer
from analyzers.s3_analyzer import S3Analyzer
from services.ec2_scanner import EC2Scanner
from services.iam_scanner import IAMScanner
from services.s3_scanner import S3Scanner
from services.risk_engine import RiskEngine

from database.persistence import persist_scan


def main():
    print("AWS Security Scanner")
    print("====================")

    # ── Scan ──────────────────────────────────────────────────────────────
    s3_scanner = S3Scanner()
    s3_scan_results = s3_scanner.scan()
    print(f"\nS3 Resources Found:  {len(s3_scan_results)}")

    ec2_scanner = EC2Scanner()
    ec2_scan_results = ec2_scanner.scan()
    print(f"EC2 Resources Found: {len(ec2_scan_results)}")

    iam_scanner = IAMScanner()
    iam_scan_results = iam_scanner.scan()
    print(f"IAM Users Found:     {len(iam_scan_results)}")

    all_scan_results = s3_scan_results + ec2_scan_results + iam_scan_results

    # ── Analyze ───────────────────────────────────────────────────────────
    s3_findings  = S3Analyzer().analyze(s3_scan_results)
    ec2_findings = EC2Analyzer().analyze(ec2_scan_results)
    iam_findings = IAMAnalyzer().analyze(iam_scan_results)

    all_findings = s3_findings + ec2_findings + iam_findings

    # ── Score ─────────────────────────────────────────────────────────────
    risk_engine = RiskEngine()
    calculated_findings = risk_engine.calculate_findings(all_findings)

    # ── Print findings ────────────────────────────────────────────────────
    print("\nSecurity Findings")
    print("-----------------")
    for finding in all_findings:
        print(f"\nRule:     {finding.rule_id}")
        print(f"Service:  {finding.service}")
        print(f"Resource: {finding.resource_id}")
        print(f"Severity: {finding.severity}")
        print(f"Status:   {finding.status}")
        print(f"Message:  {finding.message}")

    # ── Persist to Supabase ───────────────────────────────────────────────
    print("\nPersisting to database...")
    scan = persist_scan(
        scan_results=all_scan_results,
        calculated_findings=calculated_findings,
    )
    print(f"✅ Scan saved!  scan_id={scan.id}")
    print(f"   Resources:   {scan.total_resources}")
    print(f"   Findings:    {scan.total_findings}")
    print(f"   Risk Score:  {scan.total_risk_score}")


if __name__ == "__main__":
    main()
