/**
 * Orchestrates the multi-phase SecOps scan pipeline.
 *
 * A scan flows through ordered phases. The orchestrator owns every transition
 * and is the only class that enqueues the next phase. Each ingest queueable
 * is responsible only for its own work (and its own chunk-to-chunk
 * continuation), not for advancing the pipeline.
 *
 * Phase chain:
 *   LoginHistory     -> enqueue LoginHistoryIngest,       then OAuthInventory
 *   OAuthInventory   -> enqueue OAuthInventoryIngest,     then SetupAudit
 *   SetupAudit       -> enqueue SetupAuditIngest,         then PermissionChange
 *   PermissionChange -> enqueue PermissionChangeIngest,   then EventLogFile
 *   EventLogFile     -> enqueue EventLogFileIngest,       then DETECTION
 *                       (no-ops on orgs without Shield via CapabilityProbe)
 *   DETECTION        -> run DetectionEngine.evaluateAll,  then COMPLETE
 *   COMPLETE         -> finalize the Scan_Run counters and status
 */
public with sharing class ScanOrchestrator implements Queueable, Database.AllowsCallouts {
    private Id scanRunId;
    private String phase;
    private Datetime windowStart;

    /** Start a scan at the first ingest phase. */
    public ScanOrchestrator(Id scanRunId) {
        this(scanRunId, 'LoginHistory', null);
    }

    /** Resume a scan at a specific phase. */
    public ScanOrchestrator(Id scanRunId, String phase) {
        this(scanRunId, phase, null);
    }

    /**
     * Resume a scan at a specific phase with an explicit incremental window
     * start. When windowStart is non-null, ingest queueables narrow their pull
     * to events at or after that moment; when null, each ingest falls back to
     * its default lookback.
     */
    public ScanOrchestrator(Id scanRunId, String phase, Datetime windowStart) {
        this.scanRunId = scanRunId;
        this.phase = phase;
        this.windowStart = windowStart;
    }

    public void execute(QueueableContext context) {
        try {
            ScanRunService.appendLog(scanRunId, 'ScanOrchestrator: entering phase ' + phase);
            if ('LoginHistory'.equals(phase)) {
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new LoginHistoryIngest(scanRunId, windowStart));
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'OAuthInventory', windowStart));
                }
            } else if ('OAuthInventory'.equals(phase)) {
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new OAuthInventoryIngest(scanRunId, windowStart));
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'SetupAudit', windowStart));
                }
            } else if ('SetupAudit'.equals(phase)) {
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new SetupAuditIngest(scanRunId, windowStart));
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'PermissionChange', windowStart));
                }
            } else if ('PermissionChange'.equals(phase)) {
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new PermissionChangeIngest(scanRunId, windowStart));
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'EventLogFile', windowStart));
                }
            } else if ('EventLogFile'.equals(phase)) {
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new EventLogFileIngest(scanRunId, windowStart));
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'DETECTION', windowStart));
                }
            } else if ('DETECTION'.equals(phase)) {
                Integer inserted = DetectionEngine.evaluateAll(scanRunId);
                ScanRunService.appendLog(scanRunId, 'ScanOrchestrator: DETECTION inserted ' + inserted + ' findings');
                if (!Test.isRunningTest()) {
                    System.enqueueJob(new ScanOrchestrator(scanRunId, 'COMPLETE', windowStart));
                }
            } else if ('COMPLETE'.equals(phase)) {
                Integer signals = countSignals();
                Integer findings = countFindings();
                ScanRunService.complete(scanRunId, signals, findings);
            } else {
                ScanRunService.fail(scanRunId, 'ScanOrchestrator: unknown phase ' + phase);
            }
        } catch (Exception e) {
            ScanRunService.fail(scanRunId, 'ScanOrchestrator(' + phase + '): ' + e.getMessage());
        }
    }

    /**
     * Count Security_Event__c rows attached to this scan window. We approximate
     * via all rows created after the run start; a future enhancement can
     * narrow this once Security_Event__c gains a Scan_Run__c lookup.
     */
    private Integer countSignals() {
        SecOps_Scan_Run__c run = [
            SELECT Started_At__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :scanRunId
            LIMIT 1
        ];
        if (run.Started_At__c == null) {
            return 0;
        }
        return [SELECT COUNT() FROM Security_Event__c WHERE CreatedDate >= :run.Started_At__c];
    }

    /**
     * Count Security_Finding__c rows linked to this Scan_Run.
     */
    private Integer countFindings() {
        return [SELECT COUNT() FROM Security_Finding__c WHERE Scan_Run__c = :scanRunId];
    }
}
