/**
 * Ingest phase that calls the Tooling API for ConnectedApplication rows and
 * upserts OAuth_App_Inventory__c records keyed by ConnectedApp_Id__c.
 *
 * Runs as a single chunk: the Tooling API call returns the org-wide list and
 * the row count is small enough to handle without re-enqueueing.
 *
 * When complete, enqueues the next ScanOrchestrator phase (SetupAudit).
 */
public with sharing class OAuthInventoryIngest extends IngestBase {
    @SuppressWarnings('PMD.UnusedPrivateField')
    private Datetime windowStartOverride;

    public OAuthInventoryIngest(Id scanRunId) {
        super(scanRunId);
        this.windowStartOverride = null;
    }

    public OAuthInventoryIngest(Id scanRunId, Datetime windowStart) {
        super(scanRunId);
        this.windowStartOverride = windowStart;
    }

    protected override void ingest(QueueableContext context) {
        // OAuth inventory is a snapshot of the current org state, not a windowed
        // pull. The windowStart parameter is accepted for orchestrator symmetry
        // but does not narrow the Tooling API result set.
        Map<String, Map<String, Object>> apps = ConnectedAppToolingService.fetchConnectedApps();
        ScanRunService.appendLog(
            scanRunId,
            'OAuthInventoryIngest: fetched ' + apps.size() + ' ConnectedApplication rows'
        );

        if (apps.isEmpty()) {
            return;
        }

        Datetime now = Datetime.now();
        List<OAuth_App_Inventory__c> upserts = new List<OAuth_App_Inventory__c>();
        for (String connectedAppId : apps.keySet()) {
            Map<String, Object> row = apps.get(connectedAppId);
            OAuth_App_Inventory__c inv = new OAuth_App_Inventory__c(
                ConnectedApp_Id__c = connectedAppId,
                Last_Seen__c = now
            );
            Object createdDate = row.get('CreatedDate');
            if (createdDate != null) {
                try {
                    inv.Installed_Date__c = (Datetime) JSON.deserialize(
                        '"' + String.valueOf(createdDate) + '"',
                        Datetime.class
                    );
                } catch (Exception e) {
                    // ignore parse failures
                }
            }
            Object scope = row.get('Scopes');
            if (scope != null) {
                inv.Scope_Json__c = JSON.serialize(scope).left(4096);
            }
            upserts.add(inv);
        }

        try {
            Database.UpsertResult[] results = Database.upsert(
                upserts,
                OAuth_App_Inventory__c.ConnectedApp_Id__c,
                false
            );
            Integer ok = 0;
            for (Database.UpsertResult r : results) {
                if (r.isSuccess()) {
                    ok++;
                }
            }
            ScanRunService.appendLog(scanRunId, 'OAuthInventoryIngest: upserted ' + ok + ' OAuth_App_Inventory rows');
        } catch (Exception e) {
            ScanRunService.appendLog(scanRunId, 'OAuthInventoryIngest: upsert error ' + e.getMessage());
        }
    }
}
