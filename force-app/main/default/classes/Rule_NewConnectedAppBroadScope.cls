/**
 * Detection rule: flags OAuth_App_Inventory__c rows that request broad
 * OAuth scopes (api, refresh_token, full, web). New connected apps with
 * these scopes can read or modify almost any data the installing user
 * can see, so they warrant manual review.
 */
public with sharing class Rule_NewConnectedAppBroadScope implements DetectionRule {
    private static final Set<String> BROAD_SCOPES = new Set<String>{
        'api',
        'refresh_token',
        'full',
        'web',
        'chatter_api',
        'visualforce'
    };

    /** Lookback window in days for "new" connected apps. */
    private static final Integer NEW_APP_LOOKBACK_DAYS = 7;

    public String getDeveloperName() {
        return 'New_ConnectedApp_Broad_Scope';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addDays(-NEW_APP_LOOKBACK_DAYS);

        for (OAuth_App_Inventory__c app : [
            SELECT
                Id,
                Name,
                ConnectedApp_Id__c,
                Scope_Json__c,
                First_Seen__c,
                Installed_Date__c,
                Installer_User__c,
                Publisher__c
            FROM OAuth_App_Inventory__c
            WHERE First_Seen__c >= :cutoff
            LIMIT 5000
        ]) {
            List<String> broad = matchedBroadScopes(app.Scope_Json__c);
            if (broad.isEmpty()) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'OAuth Risk',
                    SecOpsConstants.SEVERITY_HIGH,
                    app.Installer_User__c,
                    app.Id,
                    String.valueOf(app.Id),
                    new Map<String, Object>{
                        'appName' => app.Name,
                        'connectedAppId' => app.ConnectedApp_Id__c,
                        'publisher' => app.Publisher__c,
                        'firstSeen' => app.First_Seen__c,
                        'broadScopes' => broad
                    }
                )
            );
        }
        return findings;
    }

    /**
     * Parse the stored scope JSON and return any scope tokens that fall
     * inside the broad-scope set. Returns an empty list when JSON is null,
     * empty, or unparseable.
     */
    private List<String> matchedBroadScopes(String scopeJson) {
        List<String> matched = new List<String>();
        if (String.isBlank(scopeJson)) {
            return matched;
        }
        try {
            Object parsed = JSON.deserializeUntyped(scopeJson);
            if (parsed instanceof List<Object>) {
                for (Object o : (List<Object>) parsed) {
                    String token = String.valueOf(o).toLowerCase();
                    if (BROAD_SCOPES.contains(token)) {
                        matched.add(token);
                    }
                }
            }
        } catch (Exception e) {
            // unparseable scope — leave matched empty
        }
        return matched;
    }
}
