@IsTest
private class Rule_NewConnectedAppBroadScope_Test {
    @IsTest
    static void broadScopeApp_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        OAuth_App_Inventory__c app = TestDataFactory.createBroadScopeApp();
        // ensure First_Seen__c is recent
        app.First_Seen__c = Datetime.now().addDays(-1);
        update app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_ConnectedApp_Broad_Scope');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_NewConnectedAppBroadScope().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'Broad-scope app should yield one finding');
        Security_Finding__c f = findings[0];
        System.assertEquals('OAuth Risk', f.Category__c);
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, f.Severity__c);
        System.assertEquals(SecOpsConstants.STATUS_NEW, f.Status__c);
        System.assertEquals(app.Id, f.Subject_App__c);
    }

    @IsTest
    static void narrowScopeApp_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        OAuth_App_Inventory__c app = TestDataFactory.createNarrowScopeApp();
        app.First_Seen__c = Datetime.now().addDays(-1);
        update app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_ConnectedApp_Broad_Scope');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        List<Security_Finding__c> findings = new Rule_NewConnectedAppBroadScope().evaluate(ctx);
        System.assertEquals(0, findings.size(), 'Narrow-scope app should not raise a finding');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('New_ConnectedApp_Broad_Scope', new Rule_NewConnectedAppBroadScope().getDeveloperName());
    }
}
