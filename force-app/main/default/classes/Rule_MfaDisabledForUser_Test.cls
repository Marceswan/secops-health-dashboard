@IsTest
private class Rule_MfaDisabledForUser_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'MFA_Disabled_For_User');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addDays(-7),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_MfaDisabledForUser().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('MFA_Disabled_For_User', new Rule_MfaDisabledForUser().getDeveloperName());
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'MFA_Disabled_For_User');
        return new DetectionContext(runId, Datetime.now().addDays(-7), Datetime.now(), false, false, cfg);
    }

    private static SetupAuditTrail trail(String action, String display) {
        return (SetupAuditTrail) JSON.deserialize(
            '{"attributes":{"type":"SetupAuditTrail"},"Id":"0Ym000000000002AAA","Action":"' +
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
        // Three independent match branches: MFA full name, MFA abbreviation, Action phrase.
        List<SetupAuditTrail> rows = new List<SetupAuditTrail>{
            trail('changedSetting', 'Multi-Factor Authentication disabled for user jdoe'),
            trail('changedSetting', 'MFA disabled for user asmith'),
            trail('Disabled Multi-Factor Authentication', 'Session settings updated')
        };

        List<Security_Finding__c> findings = Rule_MfaDisabledForUser.evaluateRows(ctx, rows);

        System.assertEquals(3, findings.size(), 'Each MFA-disable branch should fire');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
    }

    @IsTest
    static void evaluateRows_nonTriggering_producesNoFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = buildCtx(run.Id);
        List<SetupAuditTrail> rows = new List<SetupAuditTrail>{
            trail('changedSetting', 'Multi-Factor Authentication enabled for user jdoe'),
            trail('changedSetting', 'Password policy updated')
        };

        List<Security_Finding__c> findings = Rule_MfaDisabledForUser.evaluateRows(ctx, rows);

        System.assertEquals(0, findings.size(), 'Non-disable audit rows should not fire');
    }
}
