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
    // Monotonic counter guaranteeing in-transaction uniqueness across repeated
    // calls within a single test method, independent of clock resolution.
    private static Integer userSeq = 0;

    public static User standardUser() {
        Profile p = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        userSeq++;
        // Combine a high-resolution timestamp, a per-transaction sequence, and a
        // random component so Username/CommunityNickname never collide with each
        // other or with rows that already exist in the target org. The previous
        // implementation truncated this to 8 chars, which dropped the random
        // entropy and produced duplicate CommunityNickname values in orgs that
        // already held a matching nickname.
        String unique =
            String.valueOf(Datetime.now().getTime()) +
            String.valueOf(userSeq) +
            String.valueOf(Math.abs(Crypto.getRandomInteger()));
        // Alias is capped at 8 chars by the platform and is not required to be
        // unique, so a short slice is fine here.
        String alias = ('t' + userSeq + String.valueOf(Math.abs(Crypto.getRandomInteger()))).left(8);
        User u = new User(
            FirstName = 'Test',
            LastName = 'Baseline',
            Email = 'baseline.' + unique + '@example.invalid',
            Username = 'baseline.' + unique + '@secops.invalid',
            Alias = alias,
            // CommunityNickname allows up to 40 chars; keep the full unique value.
            CommunityNickname = ('tbn' + unique).left(40),
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
     * Create a user and assign one or more permission sets (by Name).
     * Performs only setup-object DML so it is safe to call from @TestSetup.
     */
    public static User userWithPermSets(Set<String> permSetNames) {
        User u = standardUser();
        assignPermSets(u.Id, permSetNames);
        return u;
    }

    /**
     * Assign permission sets (by Name) to an existing user, skipping any that
     * are already assigned. Setup-object DML only.
     */
    public static void assignPermSets(Id userId, Set<String> permSetNames) {
        Set<Id> already = new Set<Id>();
        for (PermissionSetAssignment a : [
            SELECT PermissionSetId
            FROM PermissionSetAssignment
            WHERE AssigneeId = :userId
        ]) {
            already.add(a.PermissionSetId);
        }
        List<PermissionSetAssignment> toAdd = new List<PermissionSetAssignment>();
        for (PermissionSet ps : [SELECT Id FROM PermissionSet WHERE Name IN :permSetNames]) {
            if (!already.contains(ps.Id)) {
                toAdd.add(new PermissionSetAssignment(AssigneeId = userId, PermissionSetId = ps.Id));
            }
        }
        if (!toAdd.isEmpty()) {
            insert toAdd;
        }
    }

    /**
     * Create a SecOps team user holding both the data-access set
     * (SecOps_Investigate: FLS, view/modify all findings, Action_Audit create)
     * and the destructive-remediation set (custom permissions). Use from
     * @TestSetup, then re-fetch with getEmpoweredUser() inside test methods and
     * call controllers/services via System.runAs(...). Running as a separate
     * permissioned user is required because permission-set FLS and custom
     * permissions assigned to the *current* running user do not take effect
     * within the same test execution.
     */
    public static User empoweredUser() {
        return userWithPermSets(new Set<String>{ 'SecOps_Investigate', 'SecOps_Destructive_Remediation' });
    }

    /**
     * Re-fetch the empowered SecOps user created in @TestSetup. Filters on the
     * test-only username pattern so it never returns a real org user.
     */
    public static User getEmpoweredUser() {
        return [
            SELECT Id
            FROM User
            WHERE
                Username LIKE 'baseline.%@secops.invalid'
                AND IsActive = TRUE
                AND Id IN (
                    SELECT AssigneeId
                    FROM PermissionSetAssignment
                    WHERE PermissionSet.Name = 'SecOps_Investigate'
                )
            ORDER BY CreatedDate DESC
            LIMIT 1
        ];
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
