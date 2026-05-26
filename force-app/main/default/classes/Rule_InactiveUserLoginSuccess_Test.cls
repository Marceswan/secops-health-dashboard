@IsTest
private class Rule_InactiveUserLoginSuccess_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Inactive_User_Login_Success');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_InactiveUserLoginSuccess().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Inactive_User_Login_Success', new Rule_InactiveUserLoginSuccess().getDeveloperName());
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Inactive_User_Login_Success');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory successRow(Id userId) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                userId +
                '","Status":"Success","SourceIp":"9.9.9.9","Application":"Browser","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    @IsTest
    static void evaluateRows_inactiveUser_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Set<Id> inactive = new Set<Id>{ u.Id };
        List<LoginHistory> rows = new List<LoginHistory>{ successRow(u.Id) };

        List<Security_Finding__c> findings = Rule_InactiveUserLoginSuccess.evaluateRows(
            buildCtx(run.Id),
            rows,
            inactive
        );

        System.assertEquals(1, findings.size(), 'Login by inactive user should raise one finding');
        System.assertEquals('Inactive_User_Login_Success', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_CRITICAL, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Subject user preserved');
        System.assertEquals(95, findings[0].Risk_Score__c, 'Custom risk score preserved');
    }

    @IsTest
    static void evaluateRows_activeUser_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        // User not in the inactive set => active.
        Set<Id> inactive = new Set<Id>();
        List<LoginHistory> rows = new List<LoginHistory>{ successRow(u.Id) };

        List<Security_Finding__c> findings = Rule_InactiveUserLoginSuccess.evaluateRows(
            buildCtx(run.Id),
            rows,
            inactive
        );

        System.assertEquals(0, findings.size(), 'No inactive users should not raise a finding');
    }
}
