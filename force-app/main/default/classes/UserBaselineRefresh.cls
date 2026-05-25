/**
 * Queueable that refreshes User_Baseline__c rows for every active user
 * with at least one LoginHistory row in the lookback window.
 *
 * Triggered nightly by SecOpsScheduledBaselineRefresh, or on demand.
 * Chunks the user set to stay safely under SOQL governor limits and
 * uses an existing-row lookup (since User__c is a Lookup, not an
 * external-id field) to decide insert vs. update.
 */
public with sharing class UserBaselineRefresh implements Queueable {
    public void execute(QueueableContext qc) {
        Datetime sinceWhen = Datetime.now().addDays(-SecOpsConstants.BASELINE_LOOKBACK_DAYS);

        // Find active users that have at least one Success login in the window.
        // LoginHistory.Status is not filterable in SOQL, so we filter in Apex
        // and dedupe via the Set.
        Set<Id> userIds = new Set<Id>();
        for (LoginHistory lh : [
            SELECT UserId, Status
            FROM LoginHistory
            WHERE LoginTime >= :sinceWhen
            LIMIT 50000
        ]) {
            if (lh.UserId != null && lh.Status == 'Success') {
                userIds.add(lh.UserId);
            }
        }

        if (userIds.isEmpty()) {
            return;
        }

        // Existing baselines keyed by user.
        Map<Id, User_Baseline__c> existing = BaselineEngine.loadBaselines(userIds);

        List<User_Baseline__c> toInsert = new List<User_Baseline__c>();
        List<User_Baseline__c> toUpdate = new List<User_Baseline__c>();

        for (Id uid : userIds) {
            User_Baseline__c b = BaselineEngine.buildForUser(uid, sinceWhen);
            // Always set both pointer fields (User__c is the lookup; User_Id_External__c
            // is a Text(18) external-id companion populated for parity).
            b.User__c = uid;
            b.User_Id_External__c = uid;
            User_Baseline__c prior = existing.get(uid);
            if (prior == null) {
                toInsert.add(b);
            } else {
                b.Id = prior.Id;
                toUpdate.add(b);
            }
        }

        if (!toInsert.isEmpty()) {
            insert toInsert;
        }
        if (!toUpdate.isEmpty()) {
            update toUpdate;
        }
    }
}
