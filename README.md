# SecOps Health Dashboard

A Salesforce-native security posture dashboard for consulting
engagements. Probes the org for licensed capabilities (Shield, EMS,
RTEM), runs 23 detection rules across OAuth risk, login anomalies,
privilege escalation, setup drift, and baseline deviation, and
surfaces findings in a Lightning Web Component dashboard with PDF
export. Designed to be deployed once at the start of an engagement
and operated continuously thereafter.

## Quick start

    sf org login web --alias <alias>
    sf project deploy start --target-org <alias> --manifest manifest/package.xml
    sf apex run --target-org <alias> --file scripts/apex/post-install.apex
    sf org assign permset --target-org <alias> --name SecOps_Full_Team_Access
    sf org open --target-org <alias> --path /lightning/n/SecOps_Posture

After the post-install script completes, the first scan is already in
flight. Open the Posture tab and wait for the status pill to flip to
`Completed`.

## Architecture summary

| Layer        | Component                          | Purpose                                                  |
|--------------|------------------------------------|----------------------------------------------------------|
| UI           | `secopsPosture` (LWC)              | Risk score, findings table, scan controls, PDF export.   |
| Controller   | `ScanController` (Apex)            | AuraEnabled entry point for the LWC.                     |
| Orchestrator | `ScanOrchestrator` (Queueable)     | Probes capabilities, executes rules, writes findings.    |
| Rules        | `Detection_Rule__mdt`              | 23 declarative rules gated by required capability.       |
| Data         | `Scan_Run__c`, `Finding__c`        | Persistent scan history and per-finding triage state.    |

For the full diagram and data flow see `docs/architecture.md`.

## Engagement model

The dashboard supports three operating modes. Pick one with the
customer during scoping; switch modes from the Configure tab.

- **Scan mode** (default). One-time or on-demand scans. Best for
  initial assessments and quarterly health checks. No Shield needed.
- **Continuous mode**. Adds the two weekly scheduled jobs (baseline
  refresh and cleanup) plus a daily auto-scan. Recommended for
  customers who want trend data without paying for Shield.
- **Shield mode**. Continuous mode plus the four RTEM-gated rules
  and (optionally) the real-time triggers in `optional-shield/`.
  Requires Shield or the Event Monitoring add-on.

The capability probe decides which rules are eligible. Customers
without Shield never see Shield rules misfire; the engine skips them
silently.

## Documentation

- `docs/runbooks/first-engagement.md` - day-one deploy procedure.
- `docs/runbooks/triage-playbook.md` - per-rule triage guidance.
- `docs/runbooks/shield-tier.md` - what changes when Shield is in
  play.
- `docs/runbooks/qa-checklist.md` - pre-handoff verification.
- `docs/architecture.md` - component diagram and data flow.
- `docs/superpowers/plans/` - full implementation plan and design
  spec.

## Repository layout

    force-app/main/default/      Primary package metadata
    optional-shield/             RTEM triggers and sample TSP (opt-in)
    manifest/package.xml         Deploy manifest for the main package
    scripts/apex/                Anonymous Apex utilities
    docs/                        Runbooks, architecture, plans

## Requirements

- Salesforce CLI v2.
- Target org: Enterprise Edition or higher.
- For Shield mode: Salesforce Shield or Event Monitoring add-on.
- API version 60.0+.

## Support

For questions, open an issue in the repo or contact the deploying
consultant. For incident response, follow the customer's IR playbook
first; the triage runbook is a triage aid, not a substitute for the
customer's IR process.

## License

Proprietary. Internal use by deploying consultants and authorised
customer admins only. Do not redistribute outside an active
engagement without written approval from the project owner.
