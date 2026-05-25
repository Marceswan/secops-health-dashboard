/**
 * Schedulable entry point for SecOps continuous-mode scans.
 *
 * Each fire creates a new SecOps_Scan_Run__c with Run_Type__c = 'Scheduled'
 * and enqueues a ScanOrchestrator starting at the LoginHistory phase. The
 * orchestrator carries a windowStart equal to the Completed_At__c of the
 * most recent completed scan so ingest queueables only pull data newer than
 * the last successful run; if no prior completed scan exists, the window
 * defaults to the trailing 24 hours.
 */
public with sharing class SecOpsScheduledRunner implements Schedulable {
    @TestVisible
    private static final Integer DEFAULT_LOOKBACK_HOURS = 24;

    public void execute(SchedulableContext sc) {
        Datetime windowStart = resolveWindowStart();
        Id scanRunId = ScanRunService.start(SecOpsConstants.RUN_TYPE_SCHEDULED);
        ScanRunService.appendLog(
            scanRunId,
            'SecOpsScheduledRunner: window start ' + windowStart.formatGmt('yyyy-MM-dd HH:mm:ss') + 'Z'
        );
        if (!Test.isRunningTest()) {
            System.enqueueJob(new ScanOrchestrator(scanRunId, 'LoginHistory', windowStart));
        }
    }

    /**
     * Look up the most recent completed scan and return its Completed_At__c
     * as the new window start. Falls back to a 24-hour lookback when no
     * completed scan exists yet.
     */
    private Datetime resolveWindowStart() {
        List<SecOps_Scan_Run__c> recent = [
            SELECT Id, Completed_At__c
            FROM SecOps_Scan_Run__c
            WHERE Status__c = :SecOpsConstants.SCAN_STATUS_COMPLETE AND Completed_At__c != NULL
            ORDER BY Completed_At__c DESC
            LIMIT 1
        ];
        if (!recent.isEmpty() && recent[0].Completed_At__c != null) {
            return recent[0].Completed_At__c;
        }
        return Datetime.now().addHours(-DEFAULT_LOOKBACK_HOURS);
    }
}
