/**
 * Self-chaining Queueable that refreshes User_Baseline__c rows for active
 * standard users.
 *
 * Triggered nightly by SecOpsScheduledBaselineRefresh, or on demand via
 * BaselineEngine.refreshAllNow. Users are processed in bounded chunks using
 * keyset pagination on User Id: each transaction reads only one chunk's worth
 * of LoginHistory/OauthToken rows, staying safely under the per-transaction
 * query-row governor limit even in orgs with very large login volumes. When a
 * chunk fills, the job enqueues itself for the next chunk (suppressed under
 * test execution, where only the first chunk runs).
 *
 * Only users with at least one Success login in the lookback window receive a
 * baseline; users with no qualifying logins are skipped.
 */
public with sharing class UserBaselineRefresh implements Queueable {
    // Users processed per transaction. Small enough that one chunk's
    // LoginHistory + OauthToken rows stay well under the 50k query-row limit.
    @TestVisible
    private static final Integer USER_CHUNK = 25;

    // Exclusive lower-bound cursor for keyset pagination. Null on the first run.
    private Id afterUserId;

    public UserBaselineRefresh() {
        this.afterUserId = null;
    }

    public UserBaselineRefresh(Id afterUserId) {
        this.afterUserId = afterUserId;
    }

    public void execute(QueueableContext qc) {
        Datetime sinceWhen = Datetime.now().addDays(-SecOpsConstants.BASELINE_LOOKBACK_DAYS);

        // Keyset-paginate active standard users by Id. Bounding the user set per
        // transaction keeps the downstream LoginHistory/OauthToken reads within
        // governor limits regardless of total org login volume.
        List<User> users = afterUserId == null
            ? [
                  SELECT Id
                  FROM User
                  WHERE IsActive = TRUE AND UserType = 'Standard'
                  ORDER BY Id ASC
                  LIMIT :USER_CHUNK
              ]
            : [
                  SELECT Id
                  FROM User
                  WHERE IsActive = TRUE AND UserType = 'Standard' AND Id > :afterUserId
                  ORDER BY Id ASC
                  LIMIT :USER_CHUNK
              ];

        if (users.isEmpty()) {
            return;
        }

        Set<Id> userIds = new Map<Id, User>(users).keySet();
        Map<Id, User_Baseline__c> existing = BaselineEngine.loadBaselines(userIds);
        Map<Id, User_Baseline__c> built = BaselineEngine.buildForUsers(userIds, sinceWhen);

        List<User_Baseline__c> toUpsert = new List<User_Baseline__c>();
        Id lastId = null;
        for (User uRec : users) {
            lastId = uRec.Id; // users are ordered ascending, so the final value is the max
            User_Baseline__c b = built.get(uRec.Id);
            // Skip users with no Success logins in the window (preserves the prior
            // behavior of only baselining users that actually logged in).
            if (b == null || b.Sample_Size__c == null || b.Sample_Size__c == 0) {
                continue;
            }
            // Always set both pointer fields (User__c is the lookup; User_Id_External__c
            // is a Text(18) external-id companion populated for parity).
            b.User__c = uRec.Id;
            b.User_Id_External__c = uRec.Id;
            User_Baseline__c prior = existing.get(uRec.Id);
            if (prior != null) {
                b.Id = prior.Id;
            }
            toUpsert.add(b);
        }

        if (!toUpsert.isEmpty()) {
            upsert toUpsert;
        }

        // Chain the next chunk when this one was full.
        if (users.size() == USER_CHUNK) {
            enqueueNext(lastId);
        }
    }

    /**
     * Enqueue the next pagination chunk. Suppressed under test execution, where
     * chaining queueables is disallowed; centralizing the guard here keeps the
     * call site in execute() exercised by tests.
     */
    private static void enqueueNext(Id afterUserId) {
        if (Test.isRunningTest()) {
            return;
        }
        System.enqueueJob(new UserBaselineRefresh(afterUserId));
    }
}
