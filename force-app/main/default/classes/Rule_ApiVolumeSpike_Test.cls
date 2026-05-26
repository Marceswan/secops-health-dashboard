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

    @IsTest
    static void evaluate_todaySpikeAboveThreshold_createsFinding() {
        // All ApiTotalUsage events are inserted "today" (within the last 24h),
        // so the 90-day total equals today's count. With todayCount=200:
        //   baselineAvg = 200 / 90  = 2.22, threshold = 2 * 2.22 = 4.44.
        // 200 > 4.44 AND 200 >= MIN_TODAY_COUNT(100) -> one finding.
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
        Id userId = TestDataFactory.standardUser().Id;

        List<Security_Event__c> events = new List<Security_Event__c>();
        for (Integer i = 0; i < 200; i++) {
            events.add(
                new Security_Event__c(
                    Event_Type__c = 'ApiTotalUsage',
                    Event_Time__c = Datetime.now().addHours(-1),
                    User__c = userId,
                    Source_Json__c = JSON.serialize(new Map<String, Object>{ 'count' => 1 })
                )
            );
        }
        insert events;

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ApiVolumeSpike().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'Today spike above 2x baseline should produce one finding');
        System.assertEquals('OAuth Risk', findings[0].Category__c, 'Category should be OAuth Risk');
        System.assertEquals(SecOpsConstants.SEVERITY_MEDIUM, findings[0].Severity__c, 'Severity should be Medium');
        System.assertEquals(userId, findings[0].Subject_User__c, 'Finding should reference the spiking user');
    }

    @IsTest
    static void evaluate_belowNoiseFloor_noFinding() {
        // Only 50 events today (< MIN_TODAY_COUNT of 100) -> suppressed.
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
        Id userId = TestDataFactory.standardUser().Id;

        List<Security_Event__c> events = new List<Security_Event__c>();
        for (Integer i = 0; i < 50; i++) {
            events.add(
                new Security_Event__c(
                    Event_Type__c = 'ApiTotalUsage',
                    Event_Time__c = Datetime.now().addHours(-1),
                    User__c = userId,
                    Source_Json__c = JSON.serialize(new Map<String, Object>{ 'count' => 1 })
                )
            );
        }
        insert events;

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ApiVolumeSpike().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'Volume below the 100-call noise floor should not fire');
    }
}
