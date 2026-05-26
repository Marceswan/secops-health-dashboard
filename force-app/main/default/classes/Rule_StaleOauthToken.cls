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
        Datetime cutoff = Datetime.now().addDays(-STALE_DAYS);

        List<OauthToken> tokens = [
            SELECT Id, UserId, AppName, AppMenuItem.ApplicationId, LastUsedDate, CreatedDate
            FROM OauthToken
            WHERE LastUsedDate != NULL AND LastUsedDate < :cutoff
            LIMIT 5000
        ];

        // Build the ConnectedApp_Id__c -> inventory Id lookup once, matching the
        // per-token resolution the rule previously did via per-row SOQL.
        Map<String, Id> appInventoryByConnectedAppId = new Map<String, Id>();
        for (OAuth_App_Inventory__c app : [
            SELECT Id, ConnectedApp_Id__c
            FROM OAuth_App_Inventory__c
            WHERE ConnectedApp_Id__c != NULL
            LIMIT 50000
        ]) {
            appInventoryByConnectedAppId.put(app.ConnectedApp_Id__c, app.Id);
        }

        return evaluateRows(ctx, tokens, appInventoryByConnectedAppId);
    }

    /**
     * Build a finding per stale token. Separated from the SOQL so tests can pass
     * read-only OauthToken rows (the object is not insertable) plus a pre-built
     * ConnectedApp_Id__c -> OAuth_App_Inventory__c Id map for Subject_App__c.
     */
    @TestVisible
    private static List<Security_Finding__c> evaluateRows(
        DetectionContext ctx,
        List<OauthToken> tokens,
        Map<String, Id> appInventoryByConnectedAppId
    ) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (OauthToken tok : tokens) {
            String applicationId = tok.AppMenuItem == null ? null : tok.AppMenuItem.ApplicationId;
            Id subjectAppId = String.isBlank(applicationId)
                ? null
                : appInventoryByConnectedAppId.get(applicationId);
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                'Stale_OAuth_Token',
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
}
