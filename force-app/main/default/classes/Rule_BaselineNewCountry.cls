/**
 * Detection rule: flags successful logins from a CountryIso that is not in
 * the user's warmed-up baseline Country_Set__c. New-country logins are a
 * classic indicator of credential reuse, session hijack, or travel that
 * should be verified out-of-band.
 *
 * Cold (non-warmed-up) baselines are skipped to avoid noise during the
 * initial learning window.
 */
public with sharing class Rule_BaselineNewCountry implements DetectionRule {
    /** Lookback window in hours for LoginHistory scans. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'Baseline_New_Country';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        List<LoginHistory> raw = [
            SELECT Id, UserId, CountryIso, SourceIp, LoginTime, Status
            FROM LoginHistory
            WHERE LoginTime >= :cutoff AND UserId != NULL AND CountryIso != NULL
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
            if (BaselineEngine.isCountryInBaseline(b, lh.CountryIso)) {
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
                        'country' => lh.CountryIso,
                        'sourceIp' => lh.SourceIp,
                        'loginTime' => lh.LoginTime,
                        'baselineSampleSize' => b.Sample_Size__c
                    }
                )
            );
        }
        return findings;
    }
}
