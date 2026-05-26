/**
 * Detection rule: flags connected apps that have onboarded an unusually large
 * number of distinct users in the last 24 hours. A sudden surge of users
 * granting consent to a brand-new app is a classic indicator of an OAuth
 * phishing campaign or a viral integration spreading faster than review.
 */
public with sharing class Rule_NewAppSurge implements DetectionRule {
    /** Minimum distinct users authorizing the app in the lookback window to fire. */
    private static final Integer USER_THRESHOLD = 5;
    /** Lookback window in hours. */
    private static final Integer WINDOW_HOURS = 24;

    public String getDeveloperName() {
        return 'New_App_Surge';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        // COUNT_DISTINCT(UserId) on OauthToken is not supported by the platform,
        // so we read raw tokens within the window and aggregate distinct users
        // per ApplicationId in Apex.
        List<OauthToken> tokens = [
            SELECT UserId, AppMenuItem.ApplicationId
            FROM OauthToken
            WHERE CreatedDate >= :cutoff
            LIMIT 50000
        ];

        Map<String, Integer> countByAppId = countDistinctUsersOverThreshold(tokens);

        if (countByAppId.isEmpty()) {
            return findings;
        }

        Set<String> appIds = countByAppId.keySet();

        List<OAuth_App_Inventory__c> apps = [
            SELECT Id, Name, ConnectedApp_Id__c, First_Seen__c, Publisher__c
            FROM OAuth_App_Inventory__c
            WHERE ConnectedApp_Id__c IN :appIds AND First_Seen__c >= :cutoff
            LIMIT 5000
        ];

        return evaluateRows(ctx, apps, countByAppId);
    }

    /**
     * Aggregate distinct users per connected app from raw OAuth tokens and keep
     * only apps over the surge threshold. Separated from the SOQL so tests can
     * supply in-memory OauthToken rows (the object is read-only/non-insertable).
     */
    @TestVisible
    private static Map<String, Integer> countDistinctUsersOverThreshold(List<OauthToken> tokens) {
        Map<String, Set<Id>> usersByAppId = new Map<String, Set<Id>>();
        for (OauthToken t : tokens) {
            String appId = t.AppMenuItem == null ? null : (String) t.AppMenuItem.ApplicationId;
            if (appId == null || t.UserId == null) {
                continue;
            }
            Set<Id> users = usersByAppId.get(appId);
            if (users == null) {
                users = new Set<Id>();
                usersByAppId.put(appId, users);
            }
            users.add(t.UserId);
        }

        Map<String, Integer> countByAppId = new Map<String, Integer>();
        for (String appId : usersByAppId.keySet()) {
            Integer userCount = usersByAppId.get(appId).size();
            if (userCount > USER_THRESHOLD) {
                countByAppId.put(appId, userCount);
            }
        }
        return countByAppId;
    }

    /**
     * Build a finding per surging app. Separated from the SOQL/aggregation so
     * tests can supply real OAuth_App_Inventory__c rows (insertable) plus the
     * token-derived distinct-user counts that would otherwise come from the
     * read-only OauthToken aggregation.
     */
    @TestVisible
    private static List<Security_Finding__c> evaluateRows(
        DetectionContext ctx,
        List<OAuth_App_Inventory__c> apps,
        Map<String, Integer> countByAppId
    ) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (OAuth_App_Inventory__c app : apps) {
            Integer userCount = countByAppId.get(app.ConnectedApp_Id__c);
            if (userCount == null) {
                continue;
            }
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                'New_App_Surge',
                'OAuth Risk',
                SecOpsConstants.SEVERITY_HIGH,
                null,
                app.Id,
                app.ConnectedApp_Id__c,
                new Map<String, Object>{
                    'appName' => app.Name,
                    'connectedAppId' => app.ConnectedApp_Id__c,
                    'publisher' => app.Publisher__c,
                    'firstSeen' => app.First_Seen__c,
                    'distinctUserCount' => userCount,
                    'windowHours' => WINDOW_HOURS
                }
            );
            f.Risk_Score__c = 75;
            findings.add(f);
        }
        return findings;
    }
}
