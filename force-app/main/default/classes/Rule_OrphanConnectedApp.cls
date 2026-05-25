/**
 * Detection rule: flags OAuth_App_Inventory__c rows that still hold active
 * tokens but whose installer User is inactive or missing. An orphaned
 * connected app continues to act under credentials no one owns, which is
 * a common path for stale automation to outlive its owner.
 */
public with sharing class Rule_OrphanConnectedApp implements DetectionRule {
    public String getDeveloperName() {
        return 'Orphan_ConnectedApp';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        for (OAuth_App_Inventory__c app : [
            SELECT
                Id,
                Name,
                ConnectedApp_Id__c,
                Active_Token_Count__c,
                Installer_User__c,
                Installer_User__r.IsActive,
                Installer_User__r.Username,
                Publisher__c
            FROM OAuth_App_Inventory__c
            WHERE Active_Token_Count__c > 0 AND (Installer_User__c = NULL OR Installer_User__r.IsActive = FALSE)
            LIMIT 5000
        ]) {
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'ConnectedApp Drift',
                SecOpsConstants.SEVERITY_MEDIUM,
                app.Installer_User__c,
                app.Id,
                app.ConnectedApp_Id__c,
                new Map<String, Object>{
                    'appName' => app.Name,
                    'connectedAppId' => app.ConnectedApp_Id__c,
                    'activeTokenCount' => app.Active_Token_Count__c,
                    'installerUserId' => app.Installer_User__c,
                    'installerUsername' => app.Installer_User__c == null ? null : app.Installer_User__r.Username,
                    'installerActive' => app.Installer_User__c == null ? false : app.Installer_User__r.IsActive,
                    'publisher' => app.Publisher__c
                }
            );
            f.Risk_Score__c = 50;
            findings.add(f);
        }
        return findings;
    }
}
