/**
 * Detection rule: flags users with repeated MFA-related login failures
 * inside the last 24 hours. Repeated verification failures for one user
 * are a strong signal of MFA fatigue attacks, push-bombing, or a token
 * theft attempt in progress.
 */
public with sharing class Rule_FailedMfaBurst implements DetectionRule {
    /** Minimum MFA failures from one user in the window to raise a finding. */
    private static final Integer FAILURE_THRESHOLD = 3;
    /** Lookback window in hours. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'Failed_MFA_Burst';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);
        Map<Id, Integer> failuresByUser = new Map<Id, Integer>();

        for (LoginHistory lh : [
            SELECT Id, UserId, Status, LoginTime
            FROM LoginHistory
            WHERE LoginTime >= :cutoff AND UserId != NULL
            LIMIT 50000
        ]) {
            String st = lh.Status == null ? '' : lh.Status;
            Boolean isMfaFailure =
                st.containsIgnoreCase('verification') ||
                st.containsIgnoreCase('MFA') ||
                st.containsIgnoreCase('two-factor');
            if (!isMfaFailure) {
                continue;
            }
            Integer current = failuresByUser.get(lh.UserId);
            failuresByUser.put(lh.UserId, current == null ? 1 : current + 1);
        }

        for (Id userId : failuresByUser.keySet()) {
            Integer count = failuresByUser.get(userId);
            if (count < FAILURE_THRESHOLD) {
                continue;
            }
            String sourceEventId = 'mfa-burst-' + userId + '-' + Datetime.now().getTime();
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'Login Anomaly',
                SecOpsConstants.SEVERITY_MEDIUM,
                userId,
                null,
                sourceEventId,
                new Map<String, Object>{ 'userId' => userId, 'mfaFailureCount' => count, 'windowHours' => WINDOW_HOURS }
            );
            f.Risk_Score__c = 50;
            findings.add(f);
        }
        return findings;
    }
}
