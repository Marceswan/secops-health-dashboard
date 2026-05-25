/**
 * Schedulable entry point for SecOps housekeeping.
 *
 * On each fire it:
 *  1. Kicks off ScanRunPruner to delete scan runs beyond the most-recent
 *     1000 by Started_At__c.
 *  2. Calls BaselinePruner.run() synchronously to remove baselines for
 *     inactive users.
 *
 * TODO: replacement archive mechanism for resolved findings >90 days old
 * (previously handled by FindingArchiver + Security_Finding_Archive__b Big Object,
 * now archived under archived_files/).
 */
public with sharing class SecOpsScheduledCleanup implements Schedulable {
    @TestVisible
    private static final Integer BATCH_SIZE = 200;

    public void execute(SchedulableContext sc) {
        if (!Test.isRunningTest()) {
            Database.executeBatch(new ScanRunPruner(), BATCH_SIZE);
        }
        BaselinePruner.run();
    }
}
