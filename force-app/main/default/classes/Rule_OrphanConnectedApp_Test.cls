@IsTest
private class Rule_OrphanConnectedApp_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Orphan_ConnectedApp');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_OrphanConnectedApp().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Orphan_ConnectedApp', new Rule_OrphanConnectedApp().getDeveloperName());
    }
}
