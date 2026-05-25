/**
 * Base class for SecOps ingestion Queueables.
 *
 * Each ingest job pulls a slice of source data (LoginHistory, OAuth tokens,
 * SetupAuditTrail, etc.) and writes Security_Event__c rows for downstream
 * detection. Subclasses implement {@link #ingest} and call {@link #handleError}
 * to centralize failure handling against the parent Scan_Run.
 *
 * IngestBase implements Queueable + Database.AllowsCallouts so subclasses can
 * make HTTP callouts (e.g. against the Tooling API) without re-declaring the
 * marker interface.
 */
public abstract class IngestBase implements Queueable, Database.AllowsCallouts {
    /** Parent Scan_Run that this ingest belongs to. */
    protected Id scanRunId;

    public IngestBase(Id scanRunId) {
        this.scanRunId = scanRunId;
    }

    /**
     * Entry point invoked by the Queueable framework. Wraps {@link #ingest} so
     * any subclass exception is recorded on the parent Scan_Run instead of
     * propagating into a generic flow error.
     */
    public void execute(QueueableContext context) {
        try {
            ingest(context);
        } catch (Exception e) {
            handleError(e);
        }
    }

    /**
     * Subclass-specific work. Implementations should chain themselves via
     * System.enqueueJob when more chunks remain, then enqueue the next phase
     * (typically a ScanOrchestrator transition) when their work is complete.
     */
    protected abstract void ingest(QueueableContext context);

    /**
     * Record a failure against the parent Scan_Run. Centralized so every
     * ingest phase produces a uniform error log entry.
     */
    protected virtual void handleError(Exception e) {
        ScanRunService.fail(scanRunId, this.getClassName() + ': ' + e.getMessage());
    }

    /**
     * Best-effort class name for log messages. Apex does not expose a runtime
     * "this.class.name" so subclasses can override if they need a friendlier
     * label; the default uses the typeOf-style toString from the instance.
     */
    protected virtual String getClassName() {
        return String.valueOf(this).split(':').get(0);
    }
}
