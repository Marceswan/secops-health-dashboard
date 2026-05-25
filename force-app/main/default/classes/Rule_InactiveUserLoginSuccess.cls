/**
 * Detection rule: flags successful LoginHistory entries in the last 24
 * hours that belong to a User whose IsActive is false. A successful login
 * against an inactive User typically means the account was reactivated for
 * an attack, credentials were used before the disable propagated, or a
 * service account was misclassified — all of which warrant immediate review.
 */
public with sharing class Rule_InactiveUserLoginSuccess implements DetectionRule {
    public String getDeveloperName() {
        return 'Inactive_User_Login_Success';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-24);

        List<LoginHistory> raw = [
            SELECT Id, UserId, LoginTime, SourceIp, Application, Status
            FROM LoginHistory
            WHERE LoginTime >= :cutoff AND UserId != NULL
            LIMIT 50000
        ];
        List<LoginHistory> recentSuccess = new List<LoginHistory>();
        for (LoginHistory lh : raw) {
            if (lh.Status == 'Success') {
                recentSuccess.add(lh);
            }
        }
        if (recentSuccess.isEmpty()) {
            return findings;
        }

        Set<Id> userIds = new Set<Id>();
        for (LoginHistory lh : recentSuccess) {
            userIds.add(lh.UserId);
        }

        Set<Id> inactiveUserIds = new Set<Id>();
        for (User u : [SELECT Id FROM User WHERE Id IN :userIds AND IsActive = FALSE]) {
            inactiveUserIds.add(u.Id);
        }
        if (inactiveUserIds.isEmpty()) {
            return findings;
        }

        for (LoginHistory lh : recentSuccess) {
            if (!inactiveUserIds.contains(lh.UserId)) {
                continue;
            }
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'Login Anomaly',
                SecOpsConstants.SEVERITY_CRITICAL,
                lh.UserId,
                null,
                String.valueOf(lh.Id),
                new Map<String, Object>{
                    'userId' => lh.UserId,
                    'loginTime' => lh.LoginTime,
                    'sourceIp' => lh.SourceIp,
                    'application' => lh.Application
                }
            );
            f.Risk_Score__c = 95;
            findings.add(f);
        }
        return findings;
    }
}
