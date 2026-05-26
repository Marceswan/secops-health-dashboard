@IsTest
private class Rule_MassReportExport_Test {
    @IsTest
    static void evaluate_noEvents_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Mass_Report_Export');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_MassReportExport().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No ReportExport events -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableGatedOnEventLogFile() {
        Rule_MassReportExport r = new Rule_MassReportExport();
        System.assertEquals('Mass_Report_Export', r.getDeveloperName());
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

        DetectionContext ctxWithCap = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            true,
            false,
            null
        );
        System.assertEquals(true, r.isApplicable(ctxWithCap), 'Should be applicable when EventLogFile is true');
    }

    @IsTest
    static void evaluate_overThreshold_createsFinding() {
        // 51 ReportExport events (> EXPORT_THRESHOLD of 50) in the window -> finding.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Mass_Report_Export');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        List<Security_Event__c> events = new List<Security_Event__c>();
        for (Integer i = 0; i < 51; i++) {
            events.add(
                new Security_Event__c(
                    Event_Type__c = 'ReportExport',
                    Event_Time__c = Datetime.now().addHours(-1),
                    User__c = userId,
                    Source_Json__c = JSON.serialize(new Map<String, Object>{ 'rows' => 100 })
                )
            );
        }
        insert events;

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_MassReportExport().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), '51 exports should exceed the threshold and fire once');
        System.assertEquals('OAuth Risk', findings[0].Category__c, 'Category should be OAuth Risk');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Severity should be High');
        System.assertEquals(userId, findings[0].Subject_User__c, 'Finding should reference the exporting user');
    }

    @IsTest
    static void evaluate_atThreshold_noFinding() {
        // Exactly 50 exports is NOT > 50 (HAVING COUNT(Id) > 50) -> no finding.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Mass_Report_Export');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        List<Security_Event__c> events = new List<Security_Event__c>();
        for (Integer i = 0; i < 50; i++) {
            events.add(
                new Security_Event__c(
                    Event_Type__c = 'ReportExport',
                    Event_Time__c = Datetime.now().addHours(-1),
                    User__c = userId,
                    Source_Json__c = JSON.serialize(new Map<String, Object>{ 'rows' => 100 })
                )
            );
        }
        insert events;

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_MassReportExport().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'Exactly 50 exports should not exceed the strict threshold');
    }
}
