@IsTest
private class Rule_SessionTimeoutExtended_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Session_Timeout_Extended');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-7),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_SessionTimeoutExtended().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Session_Timeout_Extended', new Rule_SessionTimeoutExtended().getDeveloperName());
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Session_Timeout_Extended');
        return new DetectionContext(runId, Datetime.now().addDays(-7), Datetime.now(), false, false, cfg);
    }

    private static SetupAuditTrail trail(String action, String display) {
        return (SetupAuditTrail) JSON.deserialize(
            '{"attributes":{"type":"SetupAuditTrail"},"Id":"0Ym000000000003AAA","Action":"' +
                action +
                '","Display":"' +
                display +
                '","CreatedById":"' +
                UserInfo.getUserId() +
                '","CreatedDate":"2026-01-15T10:00:00.000Z"}',
            SetupAuditTrail.class
        );
    }

    @IsTest
    static void evaluateRows_triggering_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = buildCtx(run.Id);
        List<SetupAuditTrail> rows = new List<SetupAuditTrail>{
            trail('changedSession', 'Session Timeout changed from 2 hours to 12 hours')
        };

        List<Security_Finding__c> findings = Rule_SessionTimeoutExtended.evaluateRows(ctx, rows);

        System.assertEquals(1, findings.size(), 'Session Timeout change should fire');
        System.assertEquals(50, findings[0].Risk_Score__c, 'Risk score should be 50');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Should be MEDIUM severity');
    }

    @IsTest
    static void evaluateRows_nonTriggering_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = buildCtx(run.Id);
        List<SetupAuditTrail> rows = new List<SetupAuditTrail>{
            trail('changedSetting', 'Password expiration changed from 90 to 180 days')
        };

        List<Security_Finding__c> findings = Rule_SessionTimeoutExtended.evaluateRows(ctx, rows);

        System.assertEquals(0, findings.size(), 'Unrelated setup changes should not fire');
    }
}
