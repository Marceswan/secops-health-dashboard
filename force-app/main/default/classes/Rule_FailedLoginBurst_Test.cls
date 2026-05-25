@IsTest
private class Rule_FailedLoginBurst_Test {
    @IsTest
    static void evaluate_noData_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_Login_Burst');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_FailedLoginBurst().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'Without LoginHistory rows there are no findings');
    }
}
