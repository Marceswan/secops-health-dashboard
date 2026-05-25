# Shield Tier Runbook

What changes when the customer has Salesforce Shield (or the Event
Monitoring add-on) licensed.

## How the package detects Shield

`CapabilityProbe` runs on every scan and on the post-install script.
It writes the result to the `Capability_Snapshot__c` record the
Configure tab reads. The probe checks:

- License presence for `EventMonitoring` and `Encryption` features.
- API availability of `RealTimeEventMonitoring` objects (e.g.
  `ApiEvent`, `LoginEventStream`, `ReportEventStream`).
- EventLogFile read access.

If the probe finds Shield, the Configure tab shows green check marks
on the EMS, RTEM, and Platform Encryption rows automatically. No
manual flag-flipping required.

## Rules that activate automatically

The detection engine checks each rule's `Required_Capability__c` field
before executing. The four Shield-only rules
(`Mass_Report_Export`, `LoginAs_Outside_Hours`, `Api_Volume_Spike`,
`Bulk_Api_From_New_Client`) all carry `RTEM` as their required
capability. When the capability probe sets `Has_RTEM__c = true`, those
rules are eligible on the next scan.

No code change needed. No metadata toggle. Deploy the package, run
post-install, and the Shield rules light up if the org qualifies.

## EventLogFile ingest

When Shield is present, the scheduled scan also runs
`EventLogFileIngest.process()` to pull the last 24 hours of log
events into staging tables that the Shield rules query. The job
respects the customer's `Async_Apex_Concurrency` setting and chunks
file pulls into 50-record batches.

If the customer's log retention is set to 1 day instead of 30, ingest
still works but trend analysis is limited to a 24-hour window.

## Optional RTEM triggers

The `optional-shield/` directory in the repo contains:

- Apex triggers on `LoginEventStream`, `ApiEventStream`, and
  `ReportEventStream`.
- A sample Transaction Security Policy (TSP) class.
- A `package.xml` manifest scoped to those components only.

These are **not** part of the default deploy because they change
runtime behaviour. Deploy only with the customer's written approval:

    sf project deploy start --target-org <alias> \
        --manifest optional-shield/package.xml

After deploy, the triggers begin enriching `Finding__c` records in
real time. The dashboard does not require them; they are an upgrade
for customers who want sub-minute detection.

## Wiring the sample TSP class

The TSP class (`SecOps_TSP_Sample.cls`) demonstrates how to block a
high-risk event before it commits. It is **not** auto-activated. To
enable in production:

1. Setup -> Transaction Security Policies -> New.
2. Event Type: choose the event the customer wants to gate (e.g.
   `LoginEvent`).
3. Apex Class: `SecOps_TSP_Sample`.
4. Action: Block, MFA challenge, or notify only - per customer
   policy.
5. Save and activate.

Test the policy against a sandbox before enabling in production. A
misconfigured TSP can lock users out.

## Verification checklist for Shield engagements

- [ ] Capability probe shows EMS, RTEM, and Platform Encryption.
- [ ] Four Shield rules appear as `Active` on the Configure tab.
- [ ] EventLogFile ingest job is registered and ran without errors.
- [ ] Optional triggers deployed only if requested.
- [ ] Sample TSP wired in Setup only if customer approved.
