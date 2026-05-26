/**
 * Detection rule: flags newly authorized OauthToken rows whose AppName is
 * not in the user's warmed-up baseline App_Set__c. A user suddenly granting
 * consent to an app they have never used before is the most common signal
 * of an OAuth-phishing campaign.
 */
public with sharing class Rule_BaselineNewApp implements DetectionRule {
    /** Lookback window in hours for OauthToken scans. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'Baseline_New_App';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        List<OauthToken> tokens = [
            SELECT Id, UserId, AppName, AppMenuItem.ApplicationId, CreatedDate, LastUsedDate
            FROM OauthToken
            WHERE CreatedDate >= :cutoff AND UserId != NULL AND AppName != NULL
            LIMIT 5000
        ];
        if (tokens.isEmpty()) {
            return findings;
        }

        Set<Id> userIds = new Set<Id>();
        for (OauthToken tok : tokens) {
            userIds.add(tok.UserId);
        }
        Map<Id, User_Baseline__c> baselines = BaselineEngine.loadBaselines(userIds);

        return evaluateRows(ctx, tokens, baselines);
    }

    /**
     * Build a finding per token whose app is outside the user's warmed-up
     * baseline. Separated from the SOQL so tests can pass read-only OauthToken
     * rows (the object is not insertable) plus a pre-built baseline map.
     */
    @TestVisible
    private static List<Security_Finding__c> evaluateRows(
        DetectionContext ctx,
        List<OauthToken> tokens,
        Map<Id, User_Baseline__c> baselines
    ) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (OauthToken tok : tokens) {
            User_Baseline__c b = baselines.get(tok.UserId);
            if (!BaselineEngine.isWarmedUp(b)) {
                continue;
            }
            if (BaselineEngine.isAppInBaseline(b, tok.AppName)) {
                continue;
            }
            String applicationId = tok.AppMenuItem == null ? null : tok.AppMenuItem.ApplicationId;
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    'Baseline_New_App',
                    'Baseline Deviation',
                    SecOpsConstants.SEVERITY_MEDIUM,
                    tok.UserId,
                    null,
                    String.valueOf(tok.Id),
                    new Map<String, Object>{
                        'tokenId' => tok.Id,
                        'appName' => tok.AppName,
                        'applicationId' => applicationId,
                        'createdDate' => tok.CreatedDate,
                        'lastUsedDate' => tok.LastUsedDate,
                        'baselineSampleSize' => b.Sample_Size__c
                    }
                )
            );
        }
        return findings;
    }
}
