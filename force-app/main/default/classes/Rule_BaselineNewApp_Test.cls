@IsTest
private class Rule_BaselineNewApp_Test {
    @IsTest
    static void evaluate_noOauthTokens_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineNewApp().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No OauthToken rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineNewApp r = new Rule_BaselineNewApp();
        System.assertEquals('Baseline_New_App', r.getDeveloperName());
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            null
        );
        System.assert(r.isApplicable(ctx), 'Rule should always be applicable');
    }

    @IsTest
    static void evaluateRows_newAppOutsideBaseline_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        // Warmed-up baseline (Sample_Size >= 20) whose App_Set does NOT contain
        // the token's AppName, so the token is flagged as a new app.
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            User_Id_External__c = u.Id,
            App_Set__c = 'Trusted App',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        // OauthToken is read-only; build it in memory via JSON.
        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000001AAA","UserId":"' +
                u.Id +
                '","AppName":"Brand New App","CreatedDate":"2026-05-25T10:00:00.000Z"}',
            OauthToken.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_BaselineNewApp.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            baselines
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'A new app outside a warmed baseline yields one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the token user');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Should be MEDIUM severity');
    }

    @IsTest
    static void evaluateRows_appInBaseline_isSuppressed() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        // Warmed-up baseline that already contains the token's app -> suppressed.
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            User_Id_External__c = u.Id,
            App_Set__c = 'Known App',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000002AAA","UserId":"' +
                u.Id +
                '","AppName":"Known App"}',
            OauthToken.class
        );

        List<Security_Finding__c> findings = Rule_BaselineNewApp.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            baselines
        );
        System.assertEquals(0, findings.size(), 'An app already in the baseline produces no finding');
    }

    @IsTest
    static void evaluateRows_coldBaseline_isSuppressed() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        // Sample_Size below the warmup threshold -> not trusted -> suppressed.
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            User_Id_External__c = u.Id,
            App_Set__c = '',
            Sample_Size__c = 1
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        OauthToken tok = (OauthToken) JSON.deserialize(
            '{"attributes":{"type":"OauthToken"},"Id":"0Da000000000003AAA","UserId":"' +
                u.Id +
                '","AppName":"Any App"}',
            OauthToken.class
        );

        List<Security_Finding__c> findings = Rule_BaselineNewApp.evaluateRows(
            ctx,
            new List<OauthToken>{ tok },
            baselines
        );
        System.assertEquals(0, findings.size(), 'A cold baseline produces no finding');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_App');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_BaselineNewApp.evaluateRows(
            ctx,
            new List<OauthToken>(),
            new Map<Id, User_Baseline__c>()
        );
        System.assertEquals(0, findings.size(), 'No tokens yields no findings');
    }
}
