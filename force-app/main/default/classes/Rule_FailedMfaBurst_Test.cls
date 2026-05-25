@IsTest
private class Rule_FailedMfaBurst_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_MFA_Burst');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_FailedMfaBurst().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Failed_MFA_Burst', new Rule_FailedMfaBurst().getDeveloperName());
    }
}
