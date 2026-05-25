// SecOps Health Dashboard - Post Install Script
// Run from the project root with:
//   sf apex run --target-org <alias> --file scripts/apex/post-install.apex
//
// Purpose:
//   1. Probe org capabilities (Shield, EMS, etc.) so the Configure tab
//      reflects what the customer actually has.
//   2. Kick off an initial Manual Scan so the Posture tab has data
//      immediately after deploy.
//   3. Register the two recurring jobs the dashboard depends on:
//        - Baseline refresh (weekly, Sunday 02:00)
//        - Cleanup / scheduled runner (weekly, Sunday 03:00)
//
// Every System.schedule call is wrapped in try/catch so that re-running
// this script in an org where the cron name already exists does not
// abort the rest of the work.

System.debug('--- SecOps post-install starting ---');

// 1. Capability probe -------------------------------------------------------
try {
    CapabilityProbe.ProbeResult caps = CapabilityProbe.runNow();
    System.debug('CapabilityProbe result: ' + caps);
} catch (Exception e) {
    System.debug(LoggingLevel.ERROR, 'CapabilityProbe failed: ' + e.getMessage());
}

// 2. Kick off the first Manual Scan ----------------------------------------
//    ScanController.startScan() inserts a Scan_Run__c and enqueues
//    ScanOrchestrator, so no extra wiring is needed here.
try {
    Id runId = ScanController.startScan();
    System.debug('Initial Scan_Run enqueued: ' + runId);
} catch (Exception e) {
    System.debug(LoggingLevel.ERROR, 'Initial scan kickoff failed: ' + e.getMessage());
}

// 3. Schedule recurring jobs -----------------------------------------------
//    Cron expression: seconds minutes hours day_of_month month day_of_week year
//    Sunday 02:00 -> '0 0 2 ? * SUN'
//    Sunday 03:00 -> '0 0 3 ? * SUN'

try {
    System.schedule(
        'SecOps Baseline Refresh - Weekly',
        '0 0 2 ? * SUN',
        new SecOpsScheduledBaselineRefresh()
    );
    System.debug('Scheduled: SecOps Baseline Refresh - Weekly (Sun 02:00)');
} catch (Exception e) {
    System.debug(LoggingLevel.WARN, 'Baseline refresh schedule skipped: ' + e.getMessage());
}

try {
    System.schedule(
        'SecOps Cleanup - Weekly',
        '0 0 3 ? * SUN',
        new SecOpsScheduledCleanup()
    );
    System.debug('Scheduled: SecOps Cleanup - Weekly (Sun 03:00)');
} catch (Exception e) {
    System.debug(LoggingLevel.WARN, 'Cleanup schedule skipped: ' + e.getMessage());
}

System.debug('--- SecOps post-install finished ---');
