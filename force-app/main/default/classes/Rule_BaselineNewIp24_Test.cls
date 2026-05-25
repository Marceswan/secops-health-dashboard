@IsTest
private class Rule_BaselineNewIp24_Test {
    @IsTest
    static void evaluate_noLoginHistory_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_Ip24');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineNewIp24().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No LoginHistory rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineNewIp24 r = new Rule_BaselineNewIp24();
        System.assertEquals('Baseline_New_Ip24', r.getDeveloperName());
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
