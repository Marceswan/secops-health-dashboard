/**
 * Batchable pruner for SecOps_Scan_Run__c rows.
 *
 * Keeps the most recent 1000 runs (ordered by Started_At__c DESC) and
 * deletes everything older. Run from SecOpsScheduledCleanup.
 */
public with sharing class ScanRunPruner implements Database.Batchable<SObject> {
    @TestVisible
    private static final Integer KEEP_COUNT = 1000;

    public Database.QueryLocator start(Database.BatchableContext bc) {
        Set<Id> keepIds = new Set<Id>();
        for (SecOps_Scan_Run__c r : [
            SELECT Id
            FROM SecOps_Scan_Run__c
            ORDER BY Started_At__c DESC NULLS LAST
            LIMIT :KEEP_COUNT
        ]) {
            keepIds.add(r.Id);
        }
        return Database.getQueryLocator(
            [
                SELECT Id
                FROM SecOps_Scan_Run__c
                WHERE Id NOT IN :keepIds
            ]
        );
    }

    public void execute(Database.BatchableContext bc, List<SecOps_Scan_Run__c> scope) {
        if (scope != null && !scope.isEmpty()) {
            delete scope;
        }
    }

    public void finish(Database.BatchableContext bc) {
        // no-op
    }
}
