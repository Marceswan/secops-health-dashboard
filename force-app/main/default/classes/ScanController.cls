/**
 * @AuraEnabled facade for the SecOps scan pipeline.
 *
 * The LWC dashboard calls {@link #startScan} to kick off a Manual Scan and
 * {@link #readLastRun} to poll the most recent SecOps_Scan_Run__c for status
 * updates.
 */
public with sharing class ScanController {
    /**
     * Start a new manual scan and return the Id of the created Scan_Run.
     */
    @AuraEnabled
    public static Id startScan() {
        try {
            Id runId = ScanRunService.start('Manual Scan');
            System.enqueueJob(new ScanOrchestrator(runId));
            return runId;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    /**
     * Return the most recent SecOps_Scan_Run__c row regardless of status, or
     * null when no runs exist. Used by the dashboard to show "last scan" info.
     */
    @AuraEnabled(cacheable=false)
    public static SecOps_Scan_Run__c readLastRun() {
        List<SecOps_Scan_Run__c> rows = [
            SELECT
                Id,
                Run_Type__c,
                Status__c,
                Started_At__c,
                Completed_At__c,
                Signals_Evaluated__c,
                Findings_Created__c,
                Error_Log__c
            FROM SecOps_Scan_Run__c
            ORDER BY CreatedDate DESC, Id DESC
            LIMIT 1
        ];
        return rows.isEmpty() ? null : rows[0];
    }
}
