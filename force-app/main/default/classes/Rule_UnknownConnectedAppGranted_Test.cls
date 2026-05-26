@IsTest
private class Rule_UnknownConnectedAppGranted_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Unknown_ConnectedApp_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_UnknownConnectedAppGranted().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Unknown_ConnectedApp_Granted', new Rule_UnknownConnectedAppGranted().getDeveloperName());
    }

    @IsTest
    static void inventorySeeded_buildsKnownSet_andReturnsList() {
        // OauthToken is not insertable in tests, so the per-token finding path
        // cannot be triggered. This seeds OAuth_App_Inventory__c so the
        // knownAppIds build loop executes against real rows.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        insert new List<OAuth_App_Inventory__c>{
            new OAuth_App_Inventory__c(
                Name = 'Known App A',
                ConnectedApp_Id__c = '0H400000000KNWN1',
                Active_Token_Count__c = 1
            ),
            new OAuth_App_Inventory__c(
                Name = 'Known App B',
                ConnectedApp_Id__c = '0H400000000KNWN2',
                Active_Token_Count__c = 1
            )
        };

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Unknown_ConnectedApp_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_UnknownConnectedAppGranted().evaluate(ctx);
        Test.stopTest();

        // No insertable tokens => no findings, but the inventory loop ran.
        System.assertEquals(0, findings.size(), 'Without OauthToken rows no unknown-grant finding can be produced');
    }

    @IsTest
    static void evaluateRows_unknownApp_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Unknown_ConnectedApp_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );

        // Known set contains a different app; the token's app is unknown.
        Set<String> knownAppIds = new Set<String>{ '0H400000000KNOWN' };

        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000020AAA","UserId":"' +
                u.Id +
                '","AppName":"Unvetted App",' +
                '"AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H400000000UNKWN"}}',
            OauthToken.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_UnknownConnectedAppGranted.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            knownAppIds
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'An uncatalogued app yields one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the token user');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Should be MEDIUM severity');
        System.assertEquals(50, findings[0].Risk_Score__c, 'Unknown-app risk score is 50');
    }

    @IsTest
    static void evaluateRows_knownAppAndNullApp_areSuppressed() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Unknown_ConnectedApp_Granted');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-30), Datetime.now(), false, false, cfg);

        Set<String> knownAppIds = new Set<String>{ '0H400000000KNOWN' };

        // Token whose app IS in the known set -> suppressed.
        OauthToken knownTok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000021AAA","UserId":"' +
                u.Id +
                '","AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H400000000KNOWN"}}',
            OauthToken.class
        );
        // Token with no AppMenuItem -> null applicationId -> skipped.
        OauthToken nullAppTok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000022AAA","UserId":"' + u.Id + '"}',
            OauthToken.class
        );

        List<Security_Finding__c> findings = Rule_UnknownConnectedAppGranted.evaluateRows(
            ctx,
            new List<OauthToken>{ knownTok, nullAppTok },
            knownAppIds
        );
        System.assertEquals(0, findings.size(), 'Known apps and null-app tokens produce no findings');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Unknown_ConnectedApp_Granted');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addDays(-30), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_UnknownConnectedAppGranted.evaluateRows(
            ctx,
            new List<OauthToken>(),
            new Set<String>()
        );
        System.assertEquals(0, findings.size(), 'No tokens yields no findings');
    }
}
