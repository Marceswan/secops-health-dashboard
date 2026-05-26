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

    @IsTest
    static void blankScopeJson_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        // Recent app but null scope JSON exercises the isBlank early return in matchedBroadScopes.
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'No Scope App',
            ConnectedApp_Id__c = '0H400000000NOSCP',
            Scope_Json__c = null,
            First_Seen__c = Datetime.now().addDays(-1),
            Active_Token_Count__c = 1
        );
        insert app;

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
        System.assertEquals(0, findings.size(), 'Blank scope JSON should not raise a finding');
    }

    @IsTest
    static void unparseableScopeJson_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        // Recent app with malformed JSON exercises the catch branch in matchedBroadScopes.
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Bad Scope App',
            ConnectedApp_Id__c = '0H400000000BADJS',
            Scope_Json__c = 'not-valid-json{',
            First_Seen__c = Datetime.now().addDays(-1),
            Active_Token_Count__c = 1
        );
        insert app;

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
        System.assertEquals(0, findings.size(), 'Unparseable scope JSON should not raise a finding');
    }

    @IsTest
    static void oldApp_outsideWindow_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        // Broad scope but First_Seen older than lookback => filtered out by the query.
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Old Broad App',
            ConnectedApp_Id__c = '0H400000000OLDBR',
            Scope_Json__c = JSON.serialize(new List<String>{ 'api', 'full' }),
            First_Seen__c = Datetime.now().addDays(-30),
            Active_Token_Count__c = 1
        );
        insert app;

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
        System.assertEquals(0, findings.size(), 'App first seen outside lookback window should not raise a finding');
    }
}
