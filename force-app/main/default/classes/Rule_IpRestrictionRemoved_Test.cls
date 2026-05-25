@IsTest
private class Rule_IpRestrictionRemoved_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'IP_Restriction_Removed');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-7),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_IpRestrictionRemoved().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('IP_Restriction_Removed', new Rule_IpRestrictionRemoved().getDeveloperName());
    }
}
