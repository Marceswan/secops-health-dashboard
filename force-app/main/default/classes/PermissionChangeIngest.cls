/**
 * Ingest phase that counts recent PermissionSetAssignment activity in the
 * 30-day window and logs the result to the parent Scan_Run.
 *
 * This phase is intentionally light — detection rules consume the underlying
 * PermissionSetAssignment data directly via DetectionContext. The ingest
 * exists so the scan log records that the permission-change window was
 * surveyed and so future enhancements can hang structured signals off it.
 */
public with sharing class PermissionChangeIngest extends IngestBase {
    private static final Integer LOOKBACK_DAYS = 30;

    private Datetime windowStartOverride;

    public PermissionChangeIngest(Id scanRunId) {
        super(scanRunId);
        this.windowStartOverride = null;
    }

    public PermissionChangeIngest(Id scanRunId, Datetime windowStart) {
        super(scanRunId);
        this.windowStartOverride = windowStart;
    }

    protected override void ingest(QueueableContext context) {
        Datetime windowStart = windowStartOverride != null
            ? windowStartOverride
            : Datetime.now().addDays(-LOOKBACK_DAYS);
        Integer count = [SELECT COUNT() FROM PermissionSetAssignment WHERE SystemModstamp >= :windowStart];
        ScanRunService.appendLog(scanRunId, buildLog(count));
    }

    /**
     * Build the survey log line from the windowed assignment count. Extracted
     * from ingest() so the count-to-message transformation is unit testable
     * without depending on org PermissionSetAssignment volume. Behavior is
     * identical to the inline logic.
     */
    @TestVisible
    private static String buildLog(Integer count) {
        return 'PermissionChangeIngest: ' + count + ' assignments in window';
    }
}
