@IsTest
private class Rule_AdminWithThirdPartyToken_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Admin_With_Third_Party_Token');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_AdminWithThirdPartyToken().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Admin_With_Third_Party_Token', new Rule_AdminWithThirdPartyToken().getDeveloperName());
    }

    @IsTest
    static void inventorySeeded_buildsAppMap_andQueriesAdmins() {
        // OauthToken is not insertable in tests, so the per-token finding path
        // cannot be triggered. This seeds OAuth_App_Inventory__c so the
        // appInventoryByConnectedAppId build loop executes, and runs the rule
        // against the org's real admin-user query.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        insert new List<OAuth_App_Inventory__c>{
            new OAuth_App_Inventory__c(
                Name = 'Mapped App A',
                ConnectedApp_Id__c = '0H400000000MAPP1',
                Active_Token_Count__c = 1
            ),
            new OAuth_App_Inventory__c(
                Name = 'Mapped App B',
                ConnectedApp_Id__c = '0H400000000MAPP2',
                Active_Token_Count__c = 1
            )
        };

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Admin_With_Third_Party_Token');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_AdminWithThirdPartyToken().evaluate(ctx);
        Test.stopTest();

        // No insertable tokens => no findings, but inventory-map build and the
        // admin-user query both executed.
        System.assertNotEquals(null, findings, 'Rule should return a non-null list');
        System.assertEquals(0, findings.size(), 'Without OauthToken rows no admin-token finding can be produced');
    }

    @IsTest
    static void evaluateRows_adminToken_producesFindingWithSubjectApp() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Mapped App',
            ConnectedApp_Id__c = '0H400000000MAPP1',
            Active_Token_Count__c = 1
        );
        insert app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Admin_With_Third_Party_Token');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Map<String, Id> appMap = new Map<String, Id>{ '0H400000000MAPP1' => app.Id };

        // OauthToken is read-only; admin filtering happens in evaluate()'s query,
        // so the token handed to evaluateRows is treated as already admin-owned.
        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000030AAA","UserId":"' +
                u.Id +
                '","AppName":"Admin App",' +
                '"AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H400000000MAPP1"}}',
            OauthToken.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_AdminWithThirdPartyToken.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            appMap
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'An admin token yields one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the token user');
        System.assertEquals(app.Id, findings[0].Subject_App__c, 'Mapped app should populate Subject_App__c');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
        System.assertEquals(75, findings[0].Risk_Score__c, 'Admin-token risk score is 75');
    }

    @IsTest
    static void evaluateRows_uncataloguedApp_findingWithoutSubjectApp() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Admin_With_Third_Party_Token');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-30), Datetime.now(), false, false, cfg);

        // No AppMenuItem -> null applicationId -> still a finding, no Subject_App.
        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000031AAA","UserId":"' +
                u.Id +
                '","AppName":"No-Menu App"}',
            OauthToken.class
        );

        List<Security_Finding__c> findings = Rule_AdminWithThirdPartyToken.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            new Map<String, Id>()
        );
        System.assertEquals(1, findings.size(), 'An admin token still yields a finding without a mapped app');
        System.assertEquals(null, findings[0].Subject_App__c, 'Unmapped app leaves Subject_App__c empty');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Admin_With_Third_Party_Token');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-30), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_AdminWithThirdPartyToken.evaluateRows(
            ctx,
            new List<OauthToken>(),
            new Map<String, Id>()
        );
        System.assertEquals(0, findings.size(), 'No tokens yields no findings');
    }
}
