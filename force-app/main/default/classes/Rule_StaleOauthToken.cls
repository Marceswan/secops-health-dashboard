/**
 * Detection rule: flags OauthToken rows that have not been used in 90+ days.
 * Stale tokens widen the attack surface — they often outlive employee
 * departures and forgotten integrations. Findings are emitted per token.
 */
public with sharing class Rule_StaleOauthToken implements DetectionRule {
    /** Tokens older than this (by LastUsedDate) are considered stale. */
    private static final Integer STALE_DAYS = 90;

    public String getDeveloperName() {
        return 'Stale_OAuth_Token';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addDays(-STALE_DAYS);

        for (OauthToken tok : [
            SELECT Id, UserId, AppName, AppMenuItem.ApplicationId, LastUsedDate, CreatedDate
            FROM OauthToken
            WHERE LastUsedDate != NULL AND LastUsedDate < :cutoff
            LIMIT 5000
        ]) {
            String applicationId = tok.AppMenuItem == null ? null : tok.AppMenuItem.ApplicationId;
            Id subjectAppId = resolveAppInventoryId(applicationId);
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'OAuth Risk',
                SecOpsConstants.SEVERITY_LOW,
                tok.UserId,
                subjectAppId,
                String.valueOf(tok.Id),
                new Map<String, Object>{
                    'tokenId' => tok.Id,
                    'appName' => tok.AppName,
                    'applicationId' => applicationId,
                    'lastUsedDate' => tok.LastUsedDate,
                    'createdDate' => tok.CreatedDate,
                    'staleThresholdDays' => STALE_DAYS
                }
            );
            f.Risk_Score__c = 25;
            findings.add(f);
        }
        return findings;
    }

    /**
     * Look up the OAuth_App_Inventory__c Id for a given ConnectedApp ApplicationId.
     * Returns null when the application is not catalogued (Subject_App__c stays empty).
     */
    private static Id resolveAppInventoryId(String applicationId) {
        if (String.isBlank(applicationId)) {
            return null;
        }
        for (OAuth_App_Inventory__c app : [
            SELECT Id
            FROM OAuth_App_Inventory__c
            WHERE ConnectedApp_Id__c = :applicationId
            LIMIT 1
        ]) {
            return app.Id;
        }
        return null;
    }
}
