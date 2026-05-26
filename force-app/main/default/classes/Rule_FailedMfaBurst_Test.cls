@IsTest
private class Rule_FailedMfaBurst_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_MFA_Burst');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_FailedMfaBurst().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Failed_MFA_Burst', new Rule_FailedMfaBurst().getDeveloperName());
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Failed_MFA_Burst');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory mfaRow(Id userId, String status) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                userId +
                '","Status":"' +
                status +
                '","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    @IsTest
    static void evaluateRows_mfaBurst_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        List<LoginHistory> rows = new List<LoginHistory>{
            mfaRow(u.Id, 'Failed: Verification'),
            mfaRow(u.Id, 'Failed: MFA challenge'),
            mfaRow(u.Id, 'Failed: two-factor required')
        };

        List<Security_Finding__c> findings = Rule_FailedMfaBurst.evaluateRows(buildCtx(run.Id), rows);

        System.assertEquals(1, findings.size(), 'Three MFA failures should raise one finding');
        System.assertEquals('Failed_MFA_Burst', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Subject user preserved');
        System.assertEquals(50, findings[0].Risk_Score__c, 'Custom risk score preserved');
    }

    @IsTest
    static void evaluateRows_belowThresholdAndNonMfa_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        List<LoginHistory> rows = new List<LoginHistory>{
            mfaRow(u.Id, 'Failed: Verification'),
            mfaRow(u.Id, 'Failed: MFA challenge'),
            // Non-MFA failures and successes must not count toward the burst.
            mfaRow(u.Id, 'Invalid Password'),
            mfaRow(u.Id, 'Success')
        };

        List<Security_Finding__c> findings = Rule_FailedMfaBurst.evaluateRows(buildCtx(run.Id), rows);

        System.assertEquals(0, findings.size(), 'Below MFA threshold should not raise a finding');
    }
}
