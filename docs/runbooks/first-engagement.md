# First Engagement Runbook

Day-one procedure for standing up the SecOps Health Dashboard in a new
customer org. Follow the steps in order. Do not skip the verification
checks between sections.

Audience: deploying consultant or admin with System Administrator access
to the target org.

Time estimate: 60-90 minutes including the customer walkthrough.

---

## Prerequisites

- Salesforce CLI v2 installed and on PATH (`sf --version`).
- Local clone of the `secops-health` repo on the `main` branch.
- Customer has granted you a temporary System Administrator user.
- You have agreed with the customer which org alias you will use.
  Document it now and use it consistently. Example: `acme-prod` or
  `acme-fullsbx`.

---

## Step 1 - Authenticate the team

Authenticate every consultant who will work on the engagement. Each
person runs:

    sf org login web --alias <alias> --instance-url <customer-instance>

Confirm the alias resolves:

    sf org display --target-org <alias>

The output must show the expected username and instance URL. If it
does not, stop and re-authenticate before continuing.

---

## Step 2 - Deploy the package

From the repo root:

    sf project deploy start --target-org <alias> --manifest manifest/package.xml

Review the output. The deploy must report `Succeeded` with zero
component failures. If any component fails, do not run post-install.
Fix the failure first and redeploy.

Optional dry-run before the real deploy:

    sf project deploy start --target-org <alias> --manifest manifest/package.xml --dry-run

---

## Step 3 - Run the post-install script

This script probes capabilities, runs the first scan, and registers
the two weekly cron jobs.

    sf apex run --target-org <alias> --file scripts/apex/post-install.apex

Verify the debug log contains:

- `CapabilityProbe result: ...`
- `Initial Scan_Run enqueued: ...`
- `Scheduled: SecOps Baseline Refresh - Weekly (Sun 02:00)`
- `Scheduled: SecOps Cleanup - Weekly (Sun 03:00)`

If a scheduled-job warning appears (`already scheduled`) the script is
safe to ignore that line; it means the cron already exists from a
prior run.

---

## Step 4 - Configure the Named Credential

The Tooling API callouts use a Named Credential called
`SecOps_Tooling_API`. This must be created manually in Setup because
the credential stores an OAuth token specific to the org.

In Setup:

1. Search for **Named Credentials** -> **New Legacy**.
2. Label: `SecOps Tooling API`. Name: `SecOps_Tooling_API`.
3. URL: the customer org's My Domain URL (for example
   `https://acme.my.salesforce.com`).
4. Identity Type: Named Principal.
5. Authentication Protocol: OAuth 2.0.
6. Auth Provider: choose the customer's Salesforce OAuth provider
   (create one if none exists).
7. Scope: `api refresh_token`.
8. Save, then click **Authenticate** and log in as the integration
   user.

Verify by running an anonymous Tooling callout from the Developer
Console; a 200 response confirms the credential is live.

---

## Step 5 - Assign permission sets

The deploying consultants need elevated access to read all SecOps
records and trigger scans. Assign the bundle permission set group:

    sf org assign permset --target-org <alias> \
        --name SecOps_Full_Team_Access

Repeat for every team member who will demo or operate the dashboard.

For end-user access, the customer's security admins should assign the
individual perm sets (`SecOps_Read`, `SecOps_Triage`, `SecOps_Admin`)
based on role. Do not assign `SecOps_Admin` to anyone outside the
deploying team during the first engagement.

---

## Step 6 - Confirm capability flags

Open the SecOps Health Dashboard app and click the **Configure** tab.
Confirm the capability matrix matches what the customer's contract
says they have:

- Event Monitoring (EMS) green check if Shield or EMS add-on is licensed.
- Real-Time Event Monitoring (RTEM) green check if Shield is licensed.
- Platform Encryption green check if Shield is licensed.

If a flag is wrong, re-run the post-install script. The probe re-reads
license info each invocation.

---

## Step 7 - Run the first scan

On the **Posture** tab, click **Run Scan Now**. The status pill should
move from `Queued` -> `Running` -> `Completed`. Typical runtime for a
medium org is 30-90 seconds.

When the scan completes, the dashboard populates:

- Risk score gauge
- Findings by severity
- Findings by category
- Open findings table

If the scan stays in `Running` for more than 5 minutes, open the
Scan Run record and check the `Error_Detail__c` field.

---

## Step 8 - Customer walkthrough

Walk the customer through the dashboard in this order:

1. **Posture tab** - explain the risk score, severity breakdown, and
   the open findings table. Click into one finding to show the detail
   panel and remediation guidance.
2. **Trends tab** - empty on day one. Explain that the trend chart
   populates after the second scheduled scan.
3. **Configure tab** - show the capability matrix and which rules are
   gated on Shield.
4. **Export** - from the Posture tab, click **Export Engagement
   Summary**. The platform generates a PDF the customer can share
   with their CISO.

Hand the PDF to the customer along with the triage playbook
(`docs/runbooks/triage-playbook.md`).

---

## Post-engagement checklist

- [ ] All scheduled jobs visible under Setup -> Scheduled Jobs.
- [ ] At least one Scan_Run record in `Completed` status.
- [ ] Capability matrix matches the customer's license tier.
- [ ] Customer received the engagement summary PDF.
- [ ] Customer admins know how to assign `SecOps_Read` to additional
      users.

If any box is unchecked, fix it before closing out day one.
