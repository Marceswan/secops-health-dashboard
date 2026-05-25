/**
 * Detection rule: flags successful logins from a /24 IP block that is not
 * in the user's warmed-up baseline Ip24_Set__c. New IP blocks indicate
 * travel, VPN/proxy use, or compromise — worth surfacing for triage.
 *
 * Rows without a parseable IPv4 SourceIp are skipped.
 */
public with sharing class Rule_BaselineNewIp24 implements DetectionRule {
    /** Lookback window in hours for LoginHistory scans. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'Baseline_New_Ip24';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        List<LoginHistory> raw = [
            SELECT Id, UserId, SourceIp, CountryIso, LoginTime, Status
            FROM LoginHistory
            WHERE LoginTime >= :cutoff AND UserId != NULL AND SourceIp != NULL
            LIMIT 50000
        ];
        List<LoginHistory> rows = new List<LoginHistory>();
        for (LoginHistory lh : raw) {
            if (lh.Status == 'Success') {
                rows.add(lh);
            }
        }
        if (rows.isEmpty()) {
            return findings;
        }

        Set<Id> userIds = new Set<Id>();
        for (LoginHistory lh : rows) {
            userIds.add(lh.UserId);
        }
        Map<Id, User_Baseline__c> baselines = BaselineEngine.loadBaselines(userIds);

        for (LoginHistory lh : rows) {
            String ip24 = BaselineEngine.toIp24(lh.SourceIp);
            if (ip24 == null) {
                continue;
            }
            User_Baseline__c b = baselines.get(lh.UserId);
            if (!BaselineEngine.isWarmedUp(b)) {
                continue;
            }
            if (BaselineEngine.isIp24InBaseline(b, ip24)) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'Baseline Deviation',
                    SecOpsConstants.SEVERITY_MEDIUM,
                    lh.UserId,
                    null,
                    String.valueOf(lh.Id),
                    new Map<String, Object>{
                        'loginHistoryId' => lh.Id,
                        'sourceIp' => lh.SourceIp,
                        'ip24' => ip24,
                        'country' => lh.CountryIso,
                        'loginTime' => lh.LoginTime,
                        'baselineSampleSize' => b.Sample_Size__c
                    }
                )
            );
        }
        return findings;
    }
}
