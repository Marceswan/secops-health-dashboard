/**
 * Unit tests for EngagementSummaryPdfController.
 *
 * Verifies every getter returns a non-null value when called against an empty
 * test context. Integer getters are zero by default which still satisfies non-null.
 */
@IsTest
private class EngagementSummaryPdfController_Test {
    @IsTest
    static void allGetters_returnNonNull() {
        EngagementSummaryPdfController c = new EngagementSummaryPdfController();

        Test.startTest();
        String generated = c.getGeneratedDate();
        String orgName = c.getOrgName();
        Integer total = c.getTotalFindings();
        Integer crit = c.getCriticalCount();
        Integer high = c.getHighCount();
        Integer apps = c.getAppCount();
        List<Map<String, Object>> top = c.getTopRisks();
        Test.stopTest();

        System.assertNotEquals(null, generated);
        System.assertNotEquals(null, orgName);
        System.assertNotEquals(null, total);
        System.assertNotEquals(null, crit);
        System.assertNotEquals(null, high);
        System.assertNotEquals(null, apps);
        System.assertNotEquals(null, top);
    }

    @IsTest
    static void getters_reflectInsertedFindings() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<Security_Finding__c> findings = new List<Security_Finding__c>{
            new Security_Finding__c(
                Detection_Rule__c = 'Test_Rule',
                Category__c = 'Login Anomaly',
                Severity__c = 'Critical',
                Status__c = 'New',
                Risk_Score__c = 90,
                Source_Event_Id__c = 'evt-pdf-1',
                Scan_Run__c = run.Id
            ),
            new Security_Finding__c(
                Detection_Rule__c = 'Test_Rule',
                Category__c = 'Login Anomaly',
                Severity__c = 'High',
                Status__c = 'Acknowledged',
                Risk_Score__c = 60,
                Source_Event_Id__c = 'evt-pdf-2',
                Scan_Run__c = run.Id
            )
        };
        insert findings;

        EngagementSummaryPdfController c = new EngagementSummaryPdfController();

        Test.startTest();
        Integer total = c.getTotalFindings();
        Integer crit = c.getCriticalCount();
        Integer high = c.getHighCount();
        Test.stopTest();

        System.assert(total >= 2, 'Total should include the two inserted findings');
        System.assert(crit >= 1, 'Critical count should reflect inserted critical');
        System.assert(high >= 1, 'High count should reflect inserted high');
    }
}
