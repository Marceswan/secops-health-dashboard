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

    @IsTest
    static void inventorySeeded_noTokens_returnsEmpty() {
        // OauthToken is not insertable in tests; the per-token finding loop and
        // the private resolveAppInventoryId helper are only reachable when token
        // rows exist, so they cannot be exercised here. Seeding inventory keeps
        // the assertion deterministic and documents the unreachable path.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        insert new OAuth_App_Inventory__c(
            Name = 'Catalogued App',
            ConnectedApp_Id__c = '0H400000000STALE',
            Active_Token_Count__c = 1
        );

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

        System.assertEquals(0, findings.size(), 'Without OauthToken rows no stale-token finding can be produced');
    }

    @IsTest
    static void evaluateRows_staleToken_producesFindingWithSubjectApp() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Catalogued App',
            ConnectedApp_Id__c = '0H400000000STALE',
            Active_Token_Count__c = 1
        );
        insert app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Stale_OAuth_Token');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-90),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Map<String, Id> appMap = new Map<String, Id>{ '0H400000000STALE' => app.Id };

        // OauthToken is read-only; build it (with nested AppMenuItem) via JSON.
        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000010AAA","UserId":"' +
                u.Id +
                '","AppName":"Old App","LastUsedDate":"2020-01-01T00:00:00.000Z",' +
                '"AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H400000000STALE"}}',
            OauthToken.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_StaleOauthToken.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            appMap
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'A stale token yields one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the token user');
        System.assertEquals(app.Id, findings[0].Subject_App__c, 'Catalogued app should populate Subject_App__c');
        System.assertEquals(SecOpsConstants.SEVERITY_LOW, findings[0].Severity__c, 'Should be LOW severity');
        System.assertEquals(25, findings[0].Risk_Score__c, 'Stale token risk score is 25');
    }

    @IsTest
    static void evaluateRows_uncataloguedApp_findingWithoutSubjectApp() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Stale_OAuth_Token');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-90), Datetime.now(), false, false, cfg);

        // Empty map -> no Subject_App link, but a finding is still produced.
        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000011AAA","UserId":"' +
                u.Id +
                '","AppName":"Unknown App","AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H400000000NOPE"}}',
            OauthToken.class
        );

        List<Security_Finding__c> findings = Rule_StaleOauthToken.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            new Map<String, Id>()
        );
        System.assertEquals(1, findings.size(), 'An uncatalogued stale token still yields a finding');
        System.assertEquals(null, findings[0].Subject_App__c, 'Uncatalogued app leaves Subject_App__c empty');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Stale_OAuth_Token');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-90), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_StaleOauthToken.evaluateRows(
            ctx,
            new List<OauthToken>(),
            new Map<String, Id>()
        );
        System.assertEquals(0, findings.size(), 'No tokens yields no findings');
    }
}
