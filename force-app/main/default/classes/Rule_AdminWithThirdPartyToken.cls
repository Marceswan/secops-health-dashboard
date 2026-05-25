/**
 * Detection rule: flags OauthToken rows whose owning user has the
 * 'System Administrator' profile. Admin users granting personal OAuth
 * tokens widen the blast radius of a credential compromise; each such
 * token is surfaced for review.
 *
 * TODO: Introduce a trusted-publisher allowlist (e.g. corporate IT-managed
 * connected apps) and suppress findings whose AppMenuItem.ApplicationId
 * matches an allowlisted publisher.
 */
public with sharing class Rule_AdminWithThirdPartyToken implements DetectionRule {
    private static final String ADMIN_PROFILE_NAME = 'System Administrator';

    public String getDeveloperName() {
        return 'Admin_With_Third_Party_Token';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        // Build a quick lookup of ConnectedApp_Id__c -> OAuth_App_Inventory__c Id
        // for Subject_App__c population. Tokens whose application is not in the
        // inventory still produce a finding, just without a Subject_App link.
        Map<String, Id> appInventoryByConnectedAppId = new Map<String, Id>();
        for (OAuth_App_Inventory__c app : [
            SELECT Id, ConnectedApp_Id__c
            FROM OAuth_App_Inventory__c
            WHERE ConnectedApp_Id__c != NULL
            LIMIT 50000
        ]) {
            appInventoryByConnectedAppId.put(app.ConnectedApp_Id__c, app.Id);
        }

        // Collect admin user ids in one query so we filter tokens locally.
        Set<Id> adminUserIds = new Set<Id>();
        for (User u : [
            SELECT Id
            FROM User
            WHERE Profile.Name = :ADMIN_PROFILE_NAME AND IsActive = TRUE
            LIMIT 5000
        ]) {
            adminUserIds.add(u.Id);
        }
        if (adminUserIds.isEmpty()) {
            return findings;
        }

        for (OauthToken tok : [
            SELECT Id, UserId, AppName, AppMenuItem.ApplicationId, LastUsedDate, CreatedDate
            FROM OauthToken
            WHERE UserId IN :adminUserIds
            LIMIT 5000
        ]) {
            String applicationId = tok.AppMenuItem == null ? null : tok.AppMenuItem.ApplicationId;
            Id subjectAppId = applicationId == null ? null : appInventoryByConnectedAppId.get(applicationId);
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'OAuth Risk',
                SecOpsConstants.SEVERITY_HIGH,
                tok.UserId,
                subjectAppId,
                String.valueOf(tok.Id),
                new Map<String, Object>{
                    'tokenId' => tok.Id,
                    'appName' => tok.AppName,
                    'applicationId' => applicationId,
                    'lastUsedDate' => tok.LastUsedDate,
                    'createdDate' => tok.CreatedDate
                }
            );
            f.Risk_Score__c = 75;
            findings.add(f);
        }
        return findings;
    }
}
