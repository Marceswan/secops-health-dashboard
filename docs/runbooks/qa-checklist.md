# QA Checklist

Pre-handoff verification for the SecOps Health Dashboard. Most checks
require a live org and must be performed by a human; this checklist
is a script, not an automated test.

Use during: every initial engagement, every package version bump,
every release candidate handed to a customer.

## Pre-deploy

- [ ] Local clone is on the intended release tag/branch.
- [ ] `sfdx-project.json` `sourceApiVersion` matches what the customer
      org supports.
- [ ] No uncommitted work in `force-app/`.

## Deploy dry-run

- [ ] `sf project deploy start --manifest manifest/package.xml \
        --target-org <alias> --dry-run` returns `Succeeded`.
- [ ] No `Will Delete` lines unless intentional.
- [ ] Zero `Will Replace` lines on production-critical metadata
      (Profile, PermissionSet) without explicit sign-off.

## Test suite

- [ ] `sf apex run test --target-org <alias> --test-level \
        RunLocalTests --result-format human --code-coverage` exits
      with status 0.
- [ ] No test failures, no compile errors.

## Coverage thresholds

- [ ] Org-wide Apex coverage >= 90%.
- [ ] Each new or modified class >= 90%.
- [ ] Trigger files >= 95% (project rule for triggers).

## Smoke scan

- [ ] Post-install script runs without exception.
- [ ] First `Scan_Run__c` reaches `Completed` within 5 minutes.
- [ ] At least one `Finding__c` record was written.
- [ ] Risk score displays on the Posture tab.

## Destructive action gating

- [ ] `Run Scan Now` requires `SecOps_Triage` or `SecOps_Admin` perm
      set.
- [ ] Resolving a finding requires `SecOps_Triage` or higher.
- [ ] Rule activation/deactivation on the Configure tab requires
      `SecOps_Admin`.
- [ ] Read-only users (`SecOps_Read`) cannot trigger a scan.

## Continuous mode toggle

- [ ] Switching to Continuous mode on the Configure tab schedules the
      baseline refresh and cleanup jobs (verify in Setup ->
      Scheduled Jobs).
- [ ] Switching back to Scan mode removes the scheduled jobs.
- [ ] No duplicate cron jobs after toggling twice.

## PDF export

- [ ] Export Engagement Summary on the Posture tab produces a PDF.
- [ ] PDF contains: org name, scan timestamp, risk score, severity
      breakdown, top 10 findings.
- [ ] PDF is under 5 MB.
- [ ] PDF renders correctly in Acrobat and in Chrome's built-in
      viewer.

## Documentation

- [ ] `README.md` exists and follows the deploy+first-scan path in
      under 20 lines of commands.
- [ ] `docs/runbooks/first-engagement.md` has all 8 steps.
- [ ] `docs/runbooks/triage-playbook.md` covers all 23 rules.
- [ ] `docs/runbooks/shield-tier.md` exists.
- [ ] `docs/runbooks/qa-checklist.md` exists (this file).
- [ ] `docs/architecture.md` exists with diagram and data flow.

## Shield-specific (only if Shield licensed)

- [ ] Capability probe reports `Has_RTEM__c = true`.
- [ ] Four Shield rules show `Active` on the Configure tab.
- [ ] EventLogFile ingest job ran in the last 24 hours.

## Sign-off

- [ ] Engagement lead initials: __________
- [ ] Date: __________
- [ ] Customer contact acknowledged handoff: __________

Do not declare the engagement complete until every applicable box is
ticked.
