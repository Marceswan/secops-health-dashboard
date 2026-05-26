/**
 * Ingest phase that pulls recent SetupAuditTrail rows into Security_Event__c
 * so detection rules can flag suspicious admin activity (permission grants,
 * profile edits, etc.).
 *
 * Reads a 30-day window by default. Runs as a single chunk because the audit
 * trail is small enough in most orgs; a future enhancement can paginate if a
 * scan window exceeds the governor limit.
 */
public with sharing class SetupAuditIngest extends IngestBase {
    private static final Integer LOOKBACK_DAYS = 30;

    private Datetime windowStartOverride;

    public SetupAuditIngest(Id scanRunId) {
        super(scanRunId);
        this.windowStartOverride = null;
    }

    public SetupAuditIngest(Id scanRunId, Datetime windowStart) {
        super(scanRunId);
        this.windowStartOverride = windowStart;
    }

    protected override void ingest(QueueableContext context) {
        Datetime windowStart = windowStartOverride != null
            ? windowStartOverride
            : Datetime.now().addDays(-LOOKBACK_DAYS);

        List<SetupAuditTrail> rows = [
            SELECT Id, Action, Display, Section, CreatedById, CreatedDate
            FROM SetupAuditTrail
            WHERE CreatedDate >= :windowStart
            ORDER BY CreatedDate ASC
            LIMIT 2000
        ];

        if (rows.isEmpty()) {
            ScanRunService.appendLog(scanRunId, 'SetupAuditIngest: no rows in 30-day window');
            return;
        }

        List<Security_Event__c> events = buildEvents(rows);

        Database.SaveResult[] results = Database.insert(events, false);
        Integer inserted = 0;
        for (Database.SaveResult sr : results) {
            if (sr.isSuccess()) {
                inserted++;
            }
        }
        ScanRunService.appendLog(scanRunId, 'SetupAuditIngest: inserted ' + inserted + ' SetupAuditTrail events');
    }

    /**
     * Transform queried SetupAuditTrail rows into Security_Event__c records.
     * Extracted from ingest() so it can be unit tested with in-memory
     * SetupAuditTrail rows (a read-only platform object that cannot be inserted
     * in tests). Behavior is identical to the inline logic.
     */
    @TestVisible
    private static List<Security_Event__c> buildEvents(List<SetupAuditTrail> rows) {
        List<Security_Event__c> events = new List<Security_Event__c>();
        for (SetupAuditTrail row : rows) {
            events.add(
                new Security_Event__c(
                    Event_Type__c = 'SetupAuditTrail',
                    Event_Time__c = row.CreatedDate,
                    User__c = row.CreatedById,
                    Source_Json__c = JSON.serialize(row)
                )
            );
        }
        return events;
    }
}
