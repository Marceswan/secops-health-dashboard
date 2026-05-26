@IsTest
private class Rule_LoginAsOutsideHours_Test {
    @IsTest
    static void evaluate_noEvents_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'LoginAs_Outside_Hours');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_LoginAsOutsideHours().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No LoginAs events -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableGatedOnEventLogFile() {
        Rule_LoginAsOutsideHours r = new Rule_LoginAsOutsideHours();
        System.assertEquals('LoginAs_Outside_Hours', r.getDeveloperName());
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctxNoCap = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            null
        );
        System.assertEquals(false, r.isApplicable(ctxNoCap), 'Should not be applicable without EventLogFile');
    }

    @IsTest
    static void evaluate_outsideBusinessHours_createsFinding() {
        // The rule reads evt.Event_Time__c.hour() (local time). Pick an event
        // time within the last 24h whose local hour is outside 08:00-18:00.
        // Walk back hour-by-hour from "now" until we land on an off-hours slot;
        // a qualifying hour always exists within any 24h span.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'LoginAs_Outside_Hours');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        Datetime offHours = null;
        for (Integer back = 1; back < 24; back++) {
            Datetime candidate = Datetime.now().addHours(-back);
            Integer hr = candidate.hour();
            if (hr < 8 || hr >= 18) {
                offHours = candidate;
                break;
            }
        }
        System.assertNotEquals(null, offHours, 'An off-hours slot must exist within 24h');

        insert new Security_Event__c(
            Event_Type__c = 'LoginAs',
            Event_Time__c = offHours,
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'DELEGATED_USER' => 'target' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_LoginAsOutsideHours().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'Off-hours LoginAs should produce one finding');
        System.assertEquals('Login Anomaly', findings[0].Category__c, 'Category should be Login Anomaly');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity should be Medium');
        System.assertEquals(userId, findings[0].Subject_User__c, 'Finding should reference the impersonating admin');
    }

    @IsTest
    static void evaluate_duringBusinessHours_noFinding() {
        // A LoginAs whose local hour is inside 08:00-18:00 must be suppressed.
        // Find an in-hours slot within the last 24h.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'LoginAs_Outside_Hours');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        Datetime inHours = null;
        for (Integer back = 1; back < 24; back++) {
            Datetime candidate = Datetime.now().addHours(-back);
            Integer hr = candidate.hour();
            if (hr >= 8 && hr < 18) {
                inHours = candidate;
                break;
            }
        }
        System.assertNotEquals(null, inHours, 'A business-hours slot must exist within 24h');

        insert new Security_Event__c(
            Event_Type__c = 'LoginAs',
            Event_Time__c = inHours,
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'DELEGATED_USER' => 'target' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_LoginAsOutsideHours().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'In-hours LoginAs should not fire');
    }
}
