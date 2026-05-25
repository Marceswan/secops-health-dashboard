/**
 * Unit tests for PostureController.
 *
 * Each test inserts a small set of findings or OAuth apps directly (rather than
 * through a rule pipeline) and asserts the controller's shape is intact and the
 * counts are non-null. Deep correctness of the SOQL is covered indirectly by the
 * rule-specific tests; here we focus on contract.
 */
@IsTest
private class PostureController_Test {
    @IsTest
    static void getRiskTrend_returnsZeroFilledWindow() {
        // Insert one Critical finding today so we get at least one non-zero row
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c f = new Security_Finding__c(
            Detection_Rule__c = 'Test_Rule',
            Category__c = 'Identity',
            Severity__c = 'Critical',
            Status__c = 'New',
            Risk_Score__c = 80,
            Scan_Run__c = run.Id
        );
        insert f;

        Test.startTest();
        List<Map<String, Object>> trend = PostureController.getRiskTrend(30);
        Test.stopTest();

        System.assertNotEquals(null, trend, 'Trend must not be null');
        System.assertEquals(30, trend.size(), 'Window must be zero-filled to 30 days');
        Map<String, Object> last = trend.get(trend.size() - 1);
        System.assert(last.containsKey('date'), 'Row must include date key');
        System.assert(last.containsKey('criticalCount'), 'Row must include criticalCount');
        System.assert(last.containsKey('highCount'), 'Row must include highCount');
    }

    @IsTest
    static void getRiskTrend_defaultsToNinetyDaysWhenNull() {
        Test.startTest();
        List<Map<String, Object>> trend = PostureController.getRiskTrend(null);
        Test.stopTest();

        System.assertNotEquals(null, trend);
        System.assertEquals(90, trend.size(), 'Default window is 90 days');
    }

    @IsTest
    static void getAppInventorySummary_returnsAllKeys() {
        OAuth_App_Inventory__c broad = TestDataFactory.createBroadScopeApp();
        broad.Risk_Flags__c = 'Broad Scope';
        broad.First_Seen__c = Datetime.now().addDays(-5);
        broad.Last_Seen__c = Datetime.now();
        update broad;

        OAuth_App_Inventory__c stale = TestDataFactory.createNarrowScopeApp();
        stale.Last_Seen__c = Datetime.now().addDays(-180);
        stale.First_Seen__c = Datetime.now().addDays(-200);
        update stale;

        Test.startTest();
        Map<String, Integer> summary = PostureController.getAppInventorySummary();
        Test.stopTest();

        System.assertNotEquals(null, summary);
        System.assert(summary.containsKey('totalApps'));
        System.assert(summary.containsKey('newIn30Days'));
        System.assert(summary.containsKey('newIn90Days'));
        System.assert(summary.containsKey('broadScopeCount'));
        System.assert(summary.containsKey('staleCount'));
        System.assert(summary.get('totalApps') >= 2, 'Total apps should include both inserts');
        System.assert(summary.get('broadScopeCount') >= 1, 'Broad scope app should be counted');
        System.assert(summary.get('staleCount') >= 1, 'Stale app should be counted');
    }

    @IsTest
    static void getTopRisks_user_returnsRows() {
        User u = TestDataFactory.standardUser();
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (Integer i = 0; i < 3; i++) {
            findings.add(
                new Security_Finding__c(
                    Detection_Rule__c = 'Test_Rule',
                    Category__c = 'Identity',
                    Severity__c = 'High',
                    Status__c = 'New',
                    Risk_Score__c = 50,
                    Subject_User__c = u.Id,
                    Scan_Run__c = run.Id
                )
            );
        }
        insert findings;

        Test.startTest();
        List<Map<String, Object>> rows = PostureController.getTopRisks('user', 5);
        Test.stopTest();

        System.assertNotEquals(null, rows);
        System.assert(rows.size() >= 1, 'Should return at least one user row');
        Map<String, Object> first = rows.get(0);
        System.assert(first.containsKey('id'));
        System.assert(first.containsKey('name'));
        System.assert(first.containsKey('findingCount'));
    }

    @IsTest
    static void getTopRisks_app_returnsRows() {
        OAuth_App_Inventory__c app = TestDataFactory.createBroadScopeApp();
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (Integer i = 0; i < 2; i++) {
            findings.add(
                new Security_Finding__c(
                    Detection_Rule__c = 'Test_Rule',
                    Category__c = 'OAuth',
                    Severity__c = 'Medium',
                    Status__c = 'New',
                    Risk_Score__c = 30,
                    Subject_App__c = app.Id,
                    Scan_Run__c = run.Id
                )
            );
        }
        insert findings;

        Test.startTest();
        List<Map<String, Object>> rows = PostureController.getTopRisks('app', 5);
        Test.stopTest();

        System.assertNotEquals(null, rows);
        System.assert(rows.size() >= 1, 'Should return at least one app row');
        Map<String, Object> first = rows.get(0);
        System.assert(first.containsKey('id'));
        System.assert(first.containsKey('name'));
        System.assert(first.containsKey('findingCount'));
    }

    @IsTest
    static void getTopRisks_unknownDimension_returnsEmpty() {
        Test.startTest();
        List<Map<String, Object>> rows = PostureController.getTopRisks('bogus', 5);
        Test.stopTest();

        System.assertNotEquals(null, rows);
        System.assertEquals(0, rows.size(), 'Unknown dimension must yield empty list');
    }
}
