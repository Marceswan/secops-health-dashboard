@IsTest
private class Rule_BaselineNewApp_Test {
    @IsTest
    static void evaluate_noOauthTokens_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineNewApp().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No OauthToken rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineNewApp r = new Rule_BaselineNewApp();
        System.assertEquals('Baseline_New_App', r.getDeveloperName());
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            null
        );
        System.assert(r.isApplicable(ctx), 'Rule should always be applicable');
    }
}
