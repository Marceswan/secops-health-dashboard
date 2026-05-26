@IsTest
private class Rule_BaselineNewCountry_Test {
    @IsTest
    static void evaluate_noLoginHistory_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_Country');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineNewCountry().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No LoginHistory rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineNewCountry r = new Rule_BaselineNewCountry();
        System.assertEquals('Baseline_New_Country', r.getDeveloperName());
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

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_Country');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory loginRow(Id userId, String country) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                userId +
                '","Status":"Success","CountryIso":"' +
                country +
                '","SourceIp":"9.9.9.9","Browser":"Chrome","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    @IsTest
    static void evaluateRows_newCountry_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Country_Set__c = 'US',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, 'CN') };

        List<Security_Finding__c> findings = Rule_BaselineNewCountry.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(1, findings.size(), 'New country should raise one finding');
        System.assertEquals('Baseline_New_Country', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Subject user preserved');
    }

    @IsTest
    static void evaluateRows_knownCountry_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Country_Set__c = 'US\nCN',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, 'CN') };

        List<Security_Finding__c> findings = Rule_BaselineNewCountry.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(0, findings.size(), 'Known country should not raise a finding');
    }

    @IsTest
    static void evaluateRows_coldBaseline_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Country_Set__c = 'US',
            Sample_Size__c = 1
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, 'CN') };

        List<Security_Finding__c> findings = Rule_BaselineNewCountry.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(0, findings.size(), 'Cold baseline should be skipped');
    }
}
