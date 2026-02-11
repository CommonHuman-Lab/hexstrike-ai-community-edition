---
name: hexstrike-reporting-skill
description: Generate comprehensive penetration testing reports with executive summaries, technical findings, and remediation guidance. Use when user asks to "generate report", "create pentest report", "document findings", "make security report", or "compile assessment results".
metadata:
  author: HexStrike AI
  version: "1.0.0"
  mcp-server: hexstrike-ai-mcp
  category: reporting
---

# HexStrike AI Reporting Skill

## Purpose

Generate professional penetration testing reports with executive summaries, detailed technical findings, risk assessments, and actionable remediation guidance. Supports multiple report formats including PDF, HTML, and JSON for different stakeholders and compliance requirements.

## Prerequisites

- Completed reconnaissance, vulnerability assessment, or exploitation phases
- Raw scan data and findings collected
- Target scope and authorization documentation
- HexStrike AI MCP server connection

## Core Workflow

### Phase 1: Data Collection and Analysis

**Gather Findings from Previous Phases**

```bash
# Collect reconnaissance data
# Collect vulnerability assessment results
# Collect exploitation evidence
# Gather logs and screenshots
```

**Data Normalization**

```python
# Normalize findings from different tools
# Standardize severity ratings (CVSS 3.1)
# Deduplicate findings across tools
# Enrich with threat intelligence
```

### Phase 2: Risk Assessment and Prioritization

**CVSS Scoring**

```python
# Calculate CVSS 3.1 scores for all vulnerabilities
# Assign business impact ratings
# Consider exploitability and exposure
# Factor in compensating controls
```

**Risk Matrix Development**

```
Risk Score = (CVSS Base Score × Business Impact) / Compensating Controls

Critical: 9.0-10.0 - Immediate action required
High: 7.0-8.9 - Address within 24-48 hours
Medium: 4.0-6.9 - Address within 1-2 weeks
Low: 0.1-3.9 - Address in next maintenance cycle
Informational: 0.0 - Best practice recommendations
```

### Phase 3: Report Generation

**Executive Summary**

```markdown
# Executive Summary

## Engagement Overview
- **Client**: [Client Name]
- **Assessment Period**: [Start Date] - [End Date]
- **Scope**: [Scope Description]
- **Methodology**: OWASP Testing Guide, PTES, NIST SP 800-115

## Key Findings
- **Critical Vulnerabilities**: [Count]
- **High Vulnerabilities**: [Count]
- **Medium Vulnerabilities**: [Count]
- **Low Vulnerabilities**: [Count]

## Overall Risk Rating
[Critical/High/Medium/Low] - [Explanation]

## Top 5 Priority Issues
1. [Critical Issue 1]
2. [Critical Issue 2]
3. [High Issue 1]
4. [High Issue 2]
5. [High Issue 3]

## Strategic Recommendations
- [High-level recommendation 1]
- [High-level recommendation 2]
- [High-level recommendation 3]
```

**Technical Findings**

```markdown
## Technical Findings

### Vulnerability: [CVE-ID or Title]
**Severity**: Critical | **CVSS**: 9.8 | **Status**: Confirmed

**Description**
Detailed technical description of the vulnerability.

**Affected Systems**
- Host: target.com
- Service: Apache HTTP Server 2.4.54
- Port: 80/TCP

**Evidence**
```

[Proof of concept code]
[Screenshots]
[Command outputs]

```

**Impact**
- Confidentiality: High
- Integrity: High
- Availability: High

**Remediation**
1. Immediate: [Short-term fix]
2. Short-term: [Configuration change]
3. Long-term: [Architecture change]

**References**
- CVE-2023-1234
- https://vendor.com/security-advisory
```

### Phase 4: Report Compilation

**Generate Multiple Formats**

**PDF Report**

```bash
# Generate professional PDF report
generate_report(
  format="pdf",
  template="pentest_executive",
  output_file="/reports/pentest-report-[client]-[date].pdf",
  sections=["executive_summary", "technical_findings", "remediation"]
)
```

**HTML Report**

```bash
# Generate interactive HTML report
generate_report(
  format="html",
  template="interactive",
  output_file="/reports/pentest-report-[client]-[date].html",
  include_charts=true,
  include_timeline=true
)
```

**JSON Report**

```bash
# Generate machine-readable JSON report
generate_report(
  format="json",
  output_file="/reports/pentest-report-[client]-[date].json",
  include_raw_data=true
)
```

**CSV Export**

```bash
# Generate spreadsheet for tracking
generate_report(
  format="csv",
  output_file="/reports/vulnerabilities-[client]-[date].csv",
  fields=["id", "title", "severity", "cvss", "status", "remediation"]
)
```

## Report Templates

### Executive Report Template

```markdown
# Penetration Test Executive Summary

## At a Glance
| Metric | Value |
|--------|-------|
| Assessment Period | [Dates] |
| Total Vulnerabilities | [Count] |
| Critical/High | [Count] |
| Risk Rating | [Rating] |

## Business Impact
[Description of business risk]

## Immediate Actions Required
1. [Action 1]
2. [Action 2]
3. [Action 3]

## Investment Recommendations
[Security improvement investments]
```

### Technical Report Template

```markdown
# Technical Assessment Report

## Methodology
- Reconnaissance: [Tools used]
- Vulnerability Assessment: [Tools used]
- Exploitation: [Tools used]
- Post-Exploitation: [Activities]

## Network Architecture
[Network diagram]

## Vulnerability Details
[Detailed technical findings]

## Exploitation Evidence
[Proof of exploitation]

## Remediation Roadmap
[Timeline and priorities]
```

### Compliance Report Template

```markdown
# Compliance Assessment Report

## Framework Coverage
- [ ] PCI DSS
- [ ] HIPAA
- [ ] SOC 2
- [ ] ISO 27001
- [ ] NIST CSF

## Control Testing
| Control | Status | Evidence | Gap |
|---------|--------|----------|-----|
| [Control] | [Pass/Fail] | [Evidence] | [Gap] |

## Compliance Score
[Score] / [Total] ([Percentage]%)

## Remediation for Compliance
[Specific compliance requirements]
```

## Report Sections

### 1. Executive Summary

- Engagement overview
- Risk summary
- Key findings
- Strategic recommendations

### 2. Methodology

- Testing approach
- Tools used
- Testing windows
- Scope and limitations

### 3. Findings Summary

- Risk distribution charts
- Vulnerability categories
- Timeline of discovery
- Severity breakdown

### 4. Technical Findings

- Detailed vulnerability descriptions
- Proof of concept
- Affected systems
- Business impact
- Technical remediation

### 5. Remediation Guidance

- Prioritized action items
- Short-term fixes
- Long-term improvements
- Resource requirements

### 6. Appendices

- Raw scan data
- Tool outputs
- Glossary
- References

## Data Visualization

### Charts and Graphs

```python
# Risk Distribution Pie Chart
# Vulnerability Timeline
# Severity by Category
# Remediation Effort vs Impact
# Compliance Score Gauge
```

### Network Diagrams

```bash
# Generate network topology
# Show attack paths
# Highlight vulnerable systems
# Display security zones
```

## Report Customization

### Branding Options

```python
# Client logo integration
# Custom color schemes
# Company watermark
# Cover page customization
```

### Content Filtering

```python
# Include/exclude sections
# Audience-specific content
# Technical detail levels
# Compliance frameworks
```

## Output Formats

### PDF Report

- Professional formatting
- Table of contents
- Page numbers
- Digital signatures

### HTML Report

- Interactive navigation
- Search functionality
- Responsive design
- Export options

### JSON Data

- Machine-readable
- Integration ready
- API compatible
- Structured data

### CSV Export

- Spreadsheet format
- Vulnerability tracking
- Import to GRC tools
- Status monitoring

## Quality Assurance

### Review Checklist

- [ ] All findings have CVSS scores
- [ ] Evidence supports findings
- [ ] Remediation steps are actionable
- [ ] No false positives included
- [ ] Client confidentiality maintained
- [ ] Technical accuracy verified
- [ ] Grammar and spelling checked
- [ ] Formatting consistent

### Peer Review Process

```bash
# Technical review
# Editorial review
# Quality assurance
# Final approval
```

## Integration with Other Skills

### From reconnaissance-skill

- Network topology data
- Service inventory
- Technology stack
- Attack surface metrics

### From vulnerability-assessment-skill

- Vulnerability findings
- CVSS scores
- Risk ratings
- Validation results

### From exploitation-skill

- Proof of exploitation
- Impact assessment
- Post-exploitation findings
- Access levels achieved

## Report Delivery

### Secure Delivery Options

```bash
# Encrypted email
# Secure file transfer
# Client portal upload
# Physical media (if required)
```

### Version Control

```bash
# Draft versions
# Review versions
# Final version
# Amendment tracking
```

## Compliance Reporting

### PCI DSS

- Requirement testing
- SAQ validation
- ASV scan integration
- Remediation tracking

### HIPAA

- Technical safeguard assessment
- Risk analysis documentation
- Security rule compliance
- Privacy rule compliance

### SOC 2

- Control testing results
- Trust service criteria
- Audit evidence
- Exception reporting

### ISO 27001

- Annex A control testing
- Statement of applicability
- Risk treatment plans
- Continuous monitoring

## Constraints and Limitations

### Data Quality

- Report accuracy depends on input data quality
- False positives may be included
- Tool limitations affect coverage
- Manual verification may be needed

### Scope Limitations

- Out-of-scope systems not assessed
- Time-constrained testing
- Limited access to internal systems
- Social engineering exclusions

### Reporting Constraints

- Sensitive data handling requirements
- Client confidentiality obligations
- Legal and regulatory considerations
- Third-party disclosure limitations

## Best Practices

### Report Writing

1. Use clear, non-technical language for executives
2. Provide specific, actionable remediation steps
3. Include evidence for all findings
4. Maintain professional tone
5. Follow consistent formatting

### Risk Communication

1. Focus on business impact
2. Use probability and impact matrices
3. Provide context for technical findings
4. Include comparative industry data
5. Highlight regulatory implications

### Remediation Guidance

1. Prioritize based on risk
2. Consider implementation effort
3. Provide alternative solutions
4. Include verification steps
5. Address root causes

## Troubleshooting

### Common Issues

**Missing Data**

- Incomplete scan results
- Tool integration failures
- Data format mismatches
- Scope gaps

**Formatting Problems**

- PDF generation errors
- Chart rendering issues
- Template compatibility
- Large file sizes

**Content Challenges**

- Unclear vulnerability descriptions
- Missing evidence
- Inconsistent severity ratings
- Incomplete remediation steps

### Resolution Steps

1. Verify data source completeness
2. Re-run failed scans
3. Standardize data formats
4. Manual review of critical findings
