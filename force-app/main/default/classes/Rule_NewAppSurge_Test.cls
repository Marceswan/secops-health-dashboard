@IsTest
private class Rule_NewAppSurge_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_App_Surge');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_NewAppSurge().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('New_App_Surge', new Rule_NewAppSurge().getDeveloperName());
    }

    @IsTest
    static void evaluateRows_surgingApp_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Viral App',
            ConnectedApp_Id__c = '0H400000000SURGE',
            Publisher__c = 'Acme',
            First_Seen__c = Datetime.now().addHours(-2),
            Active_Token_Count__c = 10
        );
        insert app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_App_Surge');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        // Distinct-user counts that would normally come from the OauthToken aggregation.
        Map<String, Integer> countByAppId = new Map<String, Integer>{ '0H400000000SURGE' => 12 };

        Test.startTest();
        List<Security_Finding__c> findings = Rule_NewAppSurge.evaluateRows(
            ctx,
            new List<OAuth_App_Inventory__c>{ app },
            countByAppId
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'A surging app yields one finding');
        System.assertEquals(app.Id, findings[0].Subject_App__c, 'Finding should target the app');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
        System.assertEquals(75, findings[0].Risk_Score__c, 'Surge risk score is 75');
    }

    @IsTest
    static void evaluateRows_appWithoutCount_isSkipped() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        OAuth_App_Inventory__c app = new OAuth_App_Inventory__c(
            Name = 'Quiet App',
            ConnectedApp_Id__c = '0H400000000QUIET',
            First_Seen__c = Datetime.now().addHours(-2),
            Active_Token_Count__c = 1
        );
        insert app;

        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_App_Surge');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        // Map has no entry for this app's ConnectedApp id -> skipped.
        List<Security_Finding__c> findings = Rule_NewAppSurge.evaluateRows(
            ctx,
            new List<OAuth_App_Inventory__c>{ app },
            new Map<String, Integer>()
        );
        System.assertEquals(0, findings.size(), 'An app with no surge count produces no finding');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'New_App_Surge');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_NewAppSurge.evaluateRows(
            ctx,
            new List<OAuth_App_Inventory__c>(),
            new Map<String, Integer>()
        );
        System.assertEquals(0, findings.size(), 'No apps yields no findings');
    }

    @IsTest
    static void countDistinctUsers_surgeAboveThreshold_isCounted() {
        // Six distinct users authorizing the same app -> over the threshold of 5.
        List<OauthToken> tokens = new List<OauthToken>();
        for (Integer i = 1; i <= 6; i++) {
            String uid = '005000000000' + String.valueOf(100 + i); // 15-char User id
            tokens.add(
                (OauthToken) JSON.deserialize(
                    '{"attributes":{"type":"OauthToken"},"UserId":"' +
                        uid +
                        '","AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H4000000000001"}}',
                    OauthToken.class
                )
            );
        }
        // A token with no app and one with no user -> both skipped.
        tokens.add(
            (OauthToken) JSON.deserialize(
                '{"attributes":{"type":"OauthToken"},"UserId":"005000000000201"}',
                OauthToken.class
            )
        );

        Map<String, Integer> counts = Rule_NewAppSurge.countDistinctUsersOverThreshold(tokens);
        // Note: the platform normalizes the 15-char ApplicationId to 18 chars when
        // deserialized into the Id-typed field, so assert on the value, not the key.
        System.assertEquals(1, counts.size(), 'Only the surging app should be counted');
        System.assertEquals(6, new List<Integer>(counts.values())[0], 'Six distinct users for the app');
    }

    @IsTest
    static void countDistinctUsers_belowThreshold_isExcluded() {
        List<OauthToken> tokens = new List<OauthToken>();
        for (Integer i = 1; i <= 3; i++) {
            String uid = '005000000000' + String.valueOf(300 + i);
            tokens.add(
                (OauthToken) JSON.deserialize(
                    '{"attributes":{"type":"OauthToken"},"UserId":"' +
                        uid +
                        '","AppMenuItem":{"attributes":{"type":"AppMenuItem"},"ApplicationId":"0H4000000000002"}}',
                    OauthToken.class
                )
            );
        }
        Map<String, Integer> counts = Rule_NewAppSurge.countDistinctUsersOverThreshold(tokens);
        System.assertEquals(0, counts.size(), 'Three users is below the surge threshold');
    }
}
