@IsTest
private class Rule_FailedLoginBurst_Test {
    @IsTest
    static void evaluate_noData_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_Login_Burst');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_FailedLoginBurst().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'Without LoginHistory rows there are no findings');
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_Login_Burst');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory failedRow(String sourceIp) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"Status":"Invalid Password","SourceIp":"' +
                sourceIp +
                '","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    private static LoginHistory successRow(String sourceIp) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"Status":"Success","SourceIp":"' +
                sourceIp +
                '","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    @IsTest
    static void evaluateRows_burst_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<LoginHistory> rows = new List<LoginHistory>();
        for (Integer i = 0; i < 10; i++) {
            rows.add(failedRow('9.9.9.9'));
        }

        List<Security_Finding__c> findings = Rule_FailedLoginBurst.evaluateRows(buildCtx(run.Id), rows);

        System.assertEquals(1, findings.size(), 'IP at threshold should raise one finding');
        System.assertEquals('Failed_Login_Burst', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals('9.9.9.9', findings[0].Source_Event_Id__c, 'Source IP used as event id');
    }

    @IsTest
    static void evaluateRows_belowThreshold_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<LoginHistory> rows = new List<LoginHistory>();
        for (Integer i = 0; i < 9; i++) {
            rows.add(failedRow('9.9.9.9'));
        }
        // Successful logins from the same IP must not count toward the burst.
        rows.add(successRow('9.9.9.9'));
        rows.add(successRow('9.9.9.9'));

        List<Security_Finding__c> findings = Rule_FailedLoginBurst.evaluateRows(buildCtx(run.Id), rows);

        System.assertEquals(0, findings.size(), 'Below threshold should not raise a finding');
    }
}
