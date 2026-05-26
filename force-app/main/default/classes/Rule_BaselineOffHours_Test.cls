@IsTest
private class Rule_BaselineOffHours_Test {
    @IsTest
    static void evaluate_noLoginHistory_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_Off_Hours');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BaselineOffHours().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No LoginHistory rows -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableAndNamed() {
        Rule_BaselineOffHours r = new Rule_BaselineOffHours();
        System.assertEquals('Baseline_Off_Hours', r.getDeveloperName());
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            null
        );
        System.assert(r.isApplicable(ctx), 'Rule should always be applicable');
    }

    private static DetectionContext buildCtx(Id runId) {
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Baseline_Off_Hours');
        return new DetectionContext(
            runId,
            Datetime.now().addDays(-30),
            Datetime.now(),
            false,
            false,
            cfg
        );
    }

    private static LoginHistory loginRow(Id userId) {
        return (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                userId +
                '","Status":"Success","CountryIso":"US","SourceIp":"9.9.9.9","Browser":"Chrome","LoginTime":"2026-01-15T03:00:00.000Z"}',
            LoginHistory.class
        );
    }

    // Build a 24-hour histogram with a heavy concentration outside the supplied
    // hour, so that hour represents < 2% of logins (anomalous). The anomalous
    // hour is derived from the row's local-time hour so the test is timezone
    // independent.
    private static String histogramAnomalousAt(Integer anomalousHour) {
        Integer[] counts = new Integer[24];
        for (Integer i = 0; i < 24; i++) {
            counts[i] = 0;
        }
        // 1000 logins on a single common hour, 0 on the anomalous hour.
        Integer commonHour = (anomalousHour == 0) ? 1 : 0;
        counts[commonHour] = 1000;
        counts[anomalousHour] = 0;
        return JSON.serialize(counts);
    }

    // Histogram where every hour is well represented, so no hour is anomalous.
    private static String histogramEven() {
        Integer[] counts = new Integer[24];
        for (Integer i = 0; i < 24; i++) {
            counts[i] = 100;
        }
        return JSON.serialize(counts);
    }

    @IsTest
    static void evaluateRows_anomalousHour_raisesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        LoginHistory lh = loginRow(u.Id);
        Integer localHour = lh.LoginTime.hour();

        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Hour_Histogram__c = histogramAnomalousAt(localHour),
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        List<Security_Finding__c> findings = Rule_BaselineOffHours.evaluateRows(
            buildCtx(run.Id),
            new List<LoginHistory>{ lh },
            baselines
        );

        System.assertEquals(1, findings.size(), 'Anomalous hour should raise one finding');
        System.assertEquals('Baseline_Off_Hours', findings[0].Detection_Rule__c, 'Rule name preserved');
        System.assertEquals(SecOpsConstants.SEVERITY_LOW, findings[0].Severity__c, 'Severity preserved');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Subject user preserved');
    }

    @IsTest
    static void evaluateRows_normalHour_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        LoginHistory lh = loginRow(u.Id);

        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Hour_Histogram__c = histogramEven(),
            Sample_Size__c = 50
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        List<Security_Finding__c> findings = Rule_BaselineOffHours.evaluateRows(
            buildCtx(run.Id),
            new List<LoginHistory>{ lh },
            baselines
        );

        System.assertEquals(0, findings.size(), 'Normal hour should not raise a finding');
    }

    @IsTest
    static void evaluateRows_coldBaseline_noFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        LoginHistory lh = loginRow(u.Id);
        Integer localHour = lh.LoginTime.hour();

        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            Hour_Histogram__c = histogramAnomalousAt(localHour),
            Sample_Size__c = 1
        );
        Map<Id, User_Baseline__c> baselines = new Map<Id, User_Baseline__c>{ u.Id => b };

        List<Security_Finding__c> findings = Rule_BaselineOffHours.evaluateRows(
            buildCtx(run.Id),
            new List<LoginHistory>{ lh },
            baselines
        );

        System.assertEquals(0, findings.size(), 'Cold baseline should be skipped');
    }
}
