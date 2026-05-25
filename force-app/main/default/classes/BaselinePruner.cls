/**
 * Deletes User_Baseline__c rows whose owning User is inactive. Not a
 * Batchable -- the active-user filter usually keeps the working set well
 * under the 10k DML row cap, and the cleanup runs alongside the heavier
 * archive/prune batches inside SecOpsScheduledCleanup.
 */
public with sharing class BaselinePruner {
    public static void run() {
        List<User_Baseline__c> stale = [
            SELECT Id
            FROM User_Baseline__c
            WHERE User__r.IsActive = FALSE
            LIMIT 10000
        ];
        if (!stale.isEmpty()) {
            delete stale;
        }
    }
}
