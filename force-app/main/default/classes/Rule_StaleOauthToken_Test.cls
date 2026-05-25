@IsTest
private class Rule_StaleOauthToken_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Stale_OAuth_Token');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-90),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_StaleOauthToken().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Stale_OAuth_Token', new Rule_StaleOauthToken().getDeveloperName());
    }
}
