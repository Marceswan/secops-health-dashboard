/**
 * Test data factory for the SecOps Health package.
 *
 * Centralizes creation of common test fixtures (Scan_Run, OAuth_App_Inventory,
 * Security_Event, Security_Finding) so tests stay short and field defaults
 * stay consistent across the suite.
 *
 * IsTest annotated so the class never counts against production code metrics.
 */
@IsTest
public class TestDataFactory {
    /**
     * Create and insert a SecOps_Scan_Run__c in Running status.
     */
    public static SecOps_Scan_Run__c createScanRun() {
        return createScanRun('Manual Scan');
    }

    public static SecOps_Scan_Run__c createScanRun(String runType) {
        SecOps_Scan_Run__c run = new SecOps_Scan_Run__c(
            Run_Type__c = runType,
            Status__c = 'Running',
            Started_At__c = Datetime.now(),
            Signals_Evaluated__c = 0
        );
        insert run;
        return run;
    }

    /**
     * Create and insert an OAuth_App_Inventory__c row with a broad scope set
     * (api refresh_token full) that should trigger the broad-scope rule.
     */
    public static OAuth_App_Inventory__c createBroadScopeApp() {
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Broad Scope Test App',
            ConnectedApp_Id__c = '0H4000000000001',
            Scope_Json__c = JSON.serialize(new List<String>{ 'api', 'refresh_token', 'full' }),
            First_Seen__c = Datetime.now().addDays(-1),
            Last_Seen__c = Datetime.now(),
            Active_Token_Count__c = 1
        );
        insert app;
        return app;
    }

    /**
     * Create and insert an OAuth_App_Inventory__c row with a narrow scope set
     * (id only) that should NOT trigger the broad-scope rule.
     */
    public static OAuth_App_Inventory__c createNarrowScopeApp() {
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Narrow Scope Test App',
            ConnectedApp_Id__c = '0H4000000000002',
            Scope_Json__c = JSON.serialize(new List<String>{ 'id' }),
            First_Seen__c = Datetime.now().addDays(-1),
            Last_Seen__c = Datetime.now(),
            Active_Token_Count__c = 1
        );
        insert app;
        return app;
    }

    /**
     * Create and insert a Standard User profile-based test user.
     *
     * Used by baseline-engine tests that need a real User Id to attach
     * User_Baseline__c rows to. Username and email are uniquified so the
     * helper can be called multiple times per test class.
     */
    public static User standardUser() {
        Profile p = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        String unique =
            String.valueOf(Datetime.now().getTime()) + String.valueOf(Math.mod(Crypto.getRandomInteger(), 1000000));
        User u = new User(
            FirstName = 'Test',
            LastName = 'Baseline',
            Email = 'baseline.' + unique + '@example.invalid',
            Username = 'baseline.' + unique + '@secops.invalid',
            Alias = 'tbl' + unique.left(5),
            CommunityNickname = 'tbn' + unique.left(8),
            TimeZoneSidKey = 'America/Los_Angeles',
            LocaleSidKey = 'en_US',
            EmailEncodingKey = 'UTF-8',
            ProfileId = p.Id,
            LanguageLocaleKey = 'en_US'
        );
        insert u;
        return u;
    }

    /**
     * Create and insert a Security_Event__c row for a synthetic LoginHistory.
     */
    public static Security_Event__c createLoginEvent(Id userId, String sourceIp, String countryCode) {
        Map<String, Object> source = new Map<String, Object>{
            'UserId' => userId,
            'SourceIp' => sourceIp,
            'CountryIso' => countryCode,
            'LoginTime' => Datetime.now()
        };
        Security_Event__c evt = new Security_Event__c(
            Event_Type__c = 'LoginHistory',
            Event_Time__c = Datetime.now(),
            User__c = userId,
            Source_Json__c = JSON.serialize(source)
        );
        insert evt;
        return evt;
    }
}
