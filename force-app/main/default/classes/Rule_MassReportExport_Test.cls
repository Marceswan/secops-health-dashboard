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
}
