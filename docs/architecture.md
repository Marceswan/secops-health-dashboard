# Architecture Overview

High-level architecture for the SecOps Health Dashboard. For the full
design spec see `docs/superpowers/plans/`. For operational procedures
see `docs/runbooks/`.

## Component diagram

    +-------------------+        +----------------------+
    |  LWC Dashboard    |  --->  |  ScanController      |
    |  (Posture / Tr.)  |        |  (Apex AuraEnabled)  |
    +-------------------+        +----------+-----------+
                                            |
                                            v
                                 +----------+-----------+
                                 |  ScanOrchestrator    |
                                 |  (Queueable)         |
                                 +----+-------+---------+
                                      |       |
                       +--------------+       +--------------+
                       v                                     v
            +----------+-----------+               +---------+----------+
            |  CapabilityProbe     |               |  DetectionEngine   |
            |  (license + RTEM)    |               |  (rule executor)   |
            +----------------------+               +---------+----------+
                                                             |
                                                             v
                                                  +----------+---------+
                                                  |  Finding__c        |
                                                  |  Scan_Run__c       |
                                                  |  Baseline__c       |
                                                  +--------------------+

## Data flow

1. User clicks **Run Scan Now** on the Posture tab.
2. `ScanController.startScan()` inserts a `Scan_Run__c` and enqueues
   `ScanOrchestrator`.
3. `ScanOrchestrator` calls `CapabilityProbe` to know which rules to
   run, then invokes `DetectionEngine` with the gated rule set.
4. `DetectionEngine` reads `Detection_Rule__mdt` and executes each
   active rule, producing `Finding__c` records.
5. LWC re-queries `Scan_Run__c` + `Finding__c` to refresh the UI.

## Scheduled jobs

- `SecOpsScheduledBaselineRefresh` - rebuilds the per-user baseline
  every Sunday 02:00.
- `SecOpsScheduledRunner` - weekly cleanup of expired findings every
  Sunday 03:00.

## Where to look

- LWC: `force-app/main/default/lwc/`
- Apex: `force-app/main/default/classes/`
- Custom metadata rules: `force-app/main/default/customMetadata/`
- Optional Shield components: `optional-shield/`
- Runbooks: `docs/runbooks/`
