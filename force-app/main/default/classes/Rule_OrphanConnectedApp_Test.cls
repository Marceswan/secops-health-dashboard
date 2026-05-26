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

    @IsTest
    static void nullInstaller_withActiveTokens_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        // Active tokens but no installer => orphan path.
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Orphan No Installer',
            ConnectedApp_Id__c = '0H400000000ORPH1',
            Active_Token_Count__c = 3,
            Installer_User__c = null,
            Publisher__c = 'Acme'
        );
        insert app;

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

        System.assertEquals(1, findings.size(), 'App with active tokens and no installer should yield one finding');
        Security_Finding__c f = findings[0];
        System.assertEquals('ConnectedApp Drift', f.Category__c);
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, f.Severity__c);
        System.assertEquals(app.Id, f.Subject_App__c);
        System.assertEquals(50, f.Risk_Score__c);
    }

    @IsTest
    static void inactiveInstaller_withActiveTokens_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        // Deactivate the installer so the IsActive = FALSE branch fires.
        u.IsActive = false;
        update u;

        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Orphan Inactive Installer',
            ConnectedApp_Id__c = '0H400000000ORPH2',
            Active_Token_Count__c = 1,
            Installer_User__c = u.Id,
            Publisher__c = 'Beta Corp'
        );
        insert app;

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

        System.assertEquals(1, findings.size(), 'App whose installer is inactive should yield one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c);
    }

    @IsTest
    static void activeInstaller_withActiveTokens_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();

        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Healthy App',
            ConnectedApp_Id__c = '0H400000000HEALT',
            Active_Token_Count__c = 1,
            Installer_User__c = u.Id
        );
        insert app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Orphan_ConnectedApp');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        List<Security_Finding__c> findings = new Rule_OrphanConnectedApp().evaluate(ctx);
        System.assertEquals(0, findings.size(), 'Active installer with active tokens should not be flagged');
    }
}
