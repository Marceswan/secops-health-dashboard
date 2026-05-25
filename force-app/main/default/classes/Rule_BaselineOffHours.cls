/**
 * Detection rule: flags successful logins that occur at an hour of day that
 * is anomalous relative to the user's warmed-up hour histogram. Off-hours
 * logins (e.g. 3 a.m. for a 9-to-5 user) often indicate an attacker using
 * stolen credentials in a different time zone.
 *
 * "Anomalous" is delegated to BaselineEngine.isHourAnomalous, which treats
 * an hour as anomalous if it represents less than 2% of historical logins.
 */
public with sharing class Rule_BaselineOffHours implements DetectionRule {
    /** Lookback window in hours for LoginHistory scans. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'Baseline_Off_Hours';
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
            WHERE LoginTime >= :cutoff AND UserId != NULL AND LoginTime != NULL
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
            User_Baseline__c b = baselines.get(lh.UserId);
            if (!BaselineEngine.isWarmedUp(b)) {
                continue;
            }
            Integer hour = lh.LoginTime.hour();
            if (!BaselineEngine.isHourAnomalous(b, hour)) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'Baseline Deviation',
                    SecOpsConstants.SEVERITY_LOW,
                    lh.UserId,
                    null,
                    String.valueOf(lh.Id),
                    new Map<String, Object>{
                        'loginHistoryId' => lh.Id,
                        'sourceIp' => lh.SourceIp,
                        'country' => lh.CountryIso,
                        'loginTime' => lh.LoginTime,
                        'hour' => hour,
                        'baselineSampleSize' => b.Sample_Size__c
                    }
                )
            );
        }
        return findings;
    }
}
