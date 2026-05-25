@IsTest
private class Rule_ApiVolumeSpike_Test {
    @IsTest
    static void evaluate_noEvents_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Api_Volume_Spike');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ApiVolumeSpike().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No ApiTotalUsage events -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableGatedOnEventLogFile() {
        Rule_ApiVolumeSpike r = new Rule_ApiVolumeSpike();
        System.assertEquals('Api_Volume_Spike', r.getDeveloperName());
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
}
