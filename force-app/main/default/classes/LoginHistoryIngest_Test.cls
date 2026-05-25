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
}
