/**
 * Detection rule: flags OauthToken rows whose underlying connected app
 * (AppMenuItem.ApplicationId) is NOT represented in OAuth_App_Inventory__c.
 *
 * The inventory is the trusted catalog of connected apps the security team
 * has reviewed. An active token referencing an application not in the
 * inventory means a user has granted access to an app that has never been
 * vetted; one finding is raised per token so triage can decide whether the
 * grant is benign or should be revoked.
 */
public with sharing class Rule_UnknownConnectedAppGranted implements DetectionRule {
    public String getDeveloperName() {
        return 'Unknown_ConnectedApp_Granted';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        // Build the set of known (vetted) ConnectedApp ids from inventory.
        Set<String> knownAppIds = new Set<String>();
        for (OAuth_App_Inventory__c app : [
            SELECT ConnectedApp_Id__c
            FROM OAuth_App_Inventory__c
            WHERE ConnectedApp_Id__c != NULL
            LIMIT 50000
        ]) {
            knownAppIds.add(app.ConnectedApp_Id__c);
        }

        List<OauthToken> tokens = [
            SELECT Id, UserId, AppName, AppMenuItem.ApplicationId, LastUsedDate, CreatedDate
            FROM OauthToken
            LIMIT 5000
        ];

        return evaluateRows(ctx, tokens, knownAppIds);
    }

    /**
     * Build a finding per token whose application is absent from the vetted set.
     * Separated from the SOQL so tests can pass read-only OauthToken rows (the
     * object is not insertable) plus a pre-built set of known ConnectedApp ids.
     */
    @TestVisible
    private static List<Security_Finding__c> evaluateRows(
        DetectionContext ctx,
        List<OauthToken> tokens,
        Set<String> knownAppIds
    ) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (OauthToken tok : tokens) {
            String applicationId = tok.AppMenuItem == null ? null : tok.AppMenuItem.ApplicationId;
            if (applicationId == null) {
                continue;
            }
            if (knownAppIds.contains(applicationId)) {
                continue;
            }
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                'Unknown_ConnectedApp_Granted',
                'OAuth Risk',
                SecOpsConstants.SEVERITY_MEDIUM,
                tok.UserId,
                null,
                String.valueOf(tok.Id),
                new Map<String, Object>{
                    'tokenId' => tok.Id,
                    'appName' => tok.AppName,
                    'applicationId' => applicationId,
                    'lastUsedDate' => tok.LastUsedDate,
                    'createdDate' => tok.CreatedDate
                }
            );
            f.Risk_Score__c = 50;
            findings.add(f);
        }
        return findings;
    }
}
