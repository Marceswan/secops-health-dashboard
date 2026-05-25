/**
 * Lifecycle service for SecOps_Scan_Run__c records.
 *
 * A "scan run" is a single end-to-end execution of the SecOps Health pipeline:
 * ingestion phases followed by detection. This service owns creating, updating,
 * and completing those rows so calling code does not duplicate DML logic.
 */
public with sharing class ScanRunService {
    /**
     * Create and insert a new SecOps_Scan_Run__c in Running status.
     *
     * @param runType One of the picklist values on Run_Type__c (e.g. 'Manual Scan').
     * @return Id of the inserted Scan_Run record.
     */
    public static Id start(String runType) {
        SecOps_Scan_Run__c run = new SecOps_Scan_Run__c(
            Run_Type__c = runType,
            Status__c = 'Running',
            Started_At__c = Datetime.now(),
            Signals_Evaluated__c = 0
        );
        insert run;
        return run.Id;
    }

    /**
     * Mark a Scan_Run complete with final counters.
     * Findings_Created__c is now a rollup summary on Security_Finding__c via the
     * Scan_Run__c master-detail, so it updates automatically and is no longer
     * assigned here. The `findingsCreated` parameter is retained for caller
     * compatibility but is no longer written to the record.
     */
    public static void complete(Id scanRunId, Integer signalsEvaluated, Integer findingsCreated) {
        SecOps_Scan_Run__c run = new SecOps_Scan_Run__c(
            Id = scanRunId,
            Status__c = 'Complete',
            Completed_At__c = Datetime.now(),
            Signals_Evaluated__c = signalsEvaluated
        );
        update run;
    }

    /**
     * Mark a Scan_Run failed and append an error message to its log.
     * Reads the current Error_Log__c so callers can append without overwriting.
     */
    public static void fail(Id scanRunId, String errorMessage) {
        SecOps_Scan_Run__c existing = [
            SELECT Id, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :scanRunId
            LIMIT 1
        ];
        String existingLog = existing.Error_Log__c == null ? '' : existing.Error_Log__c;
        String stamped = '[' + Datetime.now().formatGmt('yyyy-MM-dd HH:mm:ss') + 'Z] ' + errorMessage;
        existing.Status__c = 'Failed';
        existing.Completed_At__c = Datetime.now();
        existing.Error_Log__c = (existingLog + '\n' + stamped).left(32768);
        update existing;
    }

    /**
     * Append a timestamped line to the Error_Log__c text area without changing status.
     * Used as a general-purpose run log channel (not only for errors).
     */
    public static void appendLog(Id scanRunId, String message) {
        SecOps_Scan_Run__c existing = [
            SELECT Id, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :scanRunId
            LIMIT 1
        ];
        String existingLog = existing.Error_Log__c == null ? '' : existing.Error_Log__c;
        String stamped = '[' + Datetime.now().formatGmt('yyyy-MM-dd HH:mm:ss') + 'Z] ' + message;
        existing.Error_Log__c = (existingLog + '\n' + stamped).left(32768);
        update existing;
    }
}
