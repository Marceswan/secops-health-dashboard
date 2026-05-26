@IsTest
private class LoginHistoryIngest_Test {
    @IsTest
    static void firstChunkConstructor_initializesScanRunId() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new LoginHistoryIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Id, Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        // LoginHistory is not creatable in test context so the chunk will see
        // zero rows and log a "complete after chunk 0" line. We only assert the
        // job executed cleanly against the parent Scan_Run.
        System.assertEquals('Running', run.Status__c, 'Status should remain Running until orchestrator completes');
        System.assertNotEquals(null, run.Error_Log__c, 'Ingest should have appended at least one log line');
        System.assert(run.Error_Log__c.contains('LoginHistoryIngest'), 'Log should reference LoginHistoryIngest phase');
    }

    @IsTest
    static void chunkedConstructor_acceptsWatermark() {
        Id runId = ScanRunService.start('Scheduled');
        Datetime watermark = Datetime.now().addHours(-1);

        Test.startTest();
        System.enqueueJob(new LoginHistoryIngest(runId, 3, 50, watermark));
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assert(
            run.Error_Log__c.contains('chunk 3') || run.Error_Log__c.contains('after chunk 3'),
            'Log should reflect chunk index passed to constructor'
        );
    }

    @IsTest
    static void watermarkOf_returnsLastRowLoginTime() {
        Id uId = TestDataFactory.standardUser().Id;
        LoginHistory lh1 = (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                uId +
                '","Status":"Success","CountryIso":"US","SourceIp":"1.2.3.4","Browser":"Chrome",' +
                '"LoginTime":"2026-01-15T10:00:00.000Z"}',
            LoginHistory.class
        );
        LoginHistory lh2 = (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                uId +
                '","Status":"Success","CountryIso":"GB","SourceIp":"5.6.7.8","Browser":"Firefox",' +
                '"LoginTime":"2026-01-16T12:30:00.000Z"}',
            LoginHistory.class
        );

        Datetime watermark = LoginHistoryIngest.watermarkOf(new List<LoginHistory>{ lh1, lh2 });

        System.assertEquals(lh2.LoginTime, watermark, 'Watermark is the LoginTime of the last row');
    }

    @IsTest
    static void buildSurveyLog_formatsChunkAndCount() {
        Id uId = TestDataFactory.standardUser().Id;
        LoginHistory lh = (LoginHistory) JSON.deserialize(
            '{"attributes":{"type":"LoginHistory"},"UserId":"' +
                uId +
                '","Status":"Success","CountryIso":"US","SourceIp":"1.2.3.4","Browser":"Chrome",' +
                '"LoginTime":"2026-01-15T10:00:00.000Z"}',
            LoginHistory.class
        );

        String log = LoginHistoryIngest.buildSurveyLog(7, new List<LoginHistory>{ lh });

        System.assertEquals('LoginHistoryIngest: chunk 7 surveyed 1 rows', log, 'Log line formats chunk index and row count');
    }

    @IsTest
    static void execute_futureWindow_logsComplete() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();

        Test.startTest();
        // A future window start matches no LoginHistory -> empty/complete branch.
        new LoginHistoryIngest(run.Id, Datetime.now().addDays(2)).execute(null);
        Test.stopTest();

        SecOps_Scan_Run__c r = [SELECT Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :run.Id];
        System.assert(
            r.Error_Log__c != null && r.Error_Log__c.contains('complete'),
            'Empty window should log the completion line'
        );
    }

    @IsTest
    static void execute_allConstructors_runWithoutError() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Datetime future = Datetime.now().addDays(2);

        Test.startTest();
        // Exercise every constructor + the ingest body. Future windows keep the
        // result set empty and deterministic regardless of org login volume.
        new LoginHistoryIngest(run.Id).execute(null);
        new LoginHistoryIngest(run.Id, future).execute(null);
        new LoginHistoryIngest(run.Id, 0, 200, future).execute(null);
        new LoginHistoryIngest(run.Id, 1, 200, future, future).execute(null);
        Test.stopTest();

        System.assert(true, 'All LoginHistoryIngest constructors execute cleanly');
    }
}
