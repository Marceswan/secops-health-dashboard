@IsTest
private class Rule_IpRestrictionRemoved_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'IP_Restriction_Removed');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-7),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_IpRestrictionRemoved().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('IP_Restriction_Removed', new Rule_IpRestrictionRemoved().getDeveloperName());
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'IP_Restriction_Removed');
        return new DetectionContext(runId, Datetime.now().addDays(-7), Datetime.now(), false, false, cfg);
    }

    private static SetupAuditTrail trail(String action, String display) {
        return (SetupAuditTrail) JSON.deserialize(
            '{"attributes":{"type":"SetupAuditTrail"},"Id":"0Ym000000000001AAA","Action":"' +
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
            trail('deleted', 'Deleted Login IP Range for profile System Administrator')
        };

        List<Security_Finding__c> findings = Rule_IpRestrictionRemoved.evaluateRows(ctx, rows);

        System.assertEquals(1, findings.size(), 'Login IP Range deletion should fire');
        System.assertEquals(75, findings[0].Risk_Score__c, 'Risk score should be 75');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
    }

    @IsTest
    static void evaluateRows_nonTriggering_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = buildCtx(run.Id);
        List<SetupAuditTrail> rows = new List<SetupAuditTrail>{
            trail('changedProfile', 'Changed profile name'),
            trail('createdIpRange', 'Added Login IP Range for profile Standard User')
        };

        List<Security_Finding__c> findings = Rule_IpRestrictionRemoved.evaluateRows(ctx, rows);

        System.assertEquals(0, findings.size(), 'Non-removal audit rows should not fire');
    }
}
