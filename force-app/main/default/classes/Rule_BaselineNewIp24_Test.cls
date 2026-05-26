@IsTest
private class Rule_BaselineNewIp24_Test {
    @IsTest
    static void evaluate_noLoginHistory_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_Ip24');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineNewIp24().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No LoginHistory rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineNewIp24 r = new Rule_BaselineNewIp24();
        System.assertEquals('Baseline_New_Ip24', r.getDeveloperName());
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
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_New_Ip24');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory loginRow(Id userId, String sourceIp) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                userId +
                '","Status":"Success","CountryIso":"US","SourceIp":"' +
                sourceIp +
                '","Browser":"Chrome","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    @IsTest
    static void evaluateRows_newIp24_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Ip24_Set__c = '10.0.0.0/24',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, '9.9.9.9') };

        List<Security_Finding__c> findings = Rule_BaselineNewIp24.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(1, findings.size(), 'New /24 block should raise one finding');
        System.assertEquals('Baseline_New_Ip24', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Subject user preserved');
    }

    @IsTest
    static void evaluateRows_knownIp24_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Ip24_Set__c = '9.9.9.0/24',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, '9.9.9.9') };

        List<Security_Finding__c> findings = Rule_BaselineNewIp24.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(0, findings.size(), 'Known /24 block should not raise a finding');
    }

    @IsTest
    static void evaluateRows_unparseableIp_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Ip24_Set__c = '10.0.0.0/24',
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };
        List<LoginHistory> rows = new List<LoginHistory>{ loginRow(u.Id, 'not-an-ip') };

        List<Security_Finding__c> findings = Rule_BaselineNewIp24.evaluateRows(
            buildCtx(run.Id),
            rows,
            baselines
        );

        System.assertEquals(0, findings.size(), 'Unparseable IP should be skipped');
    }
}
