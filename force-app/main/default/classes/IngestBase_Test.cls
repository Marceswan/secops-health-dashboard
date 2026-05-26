@IsTest
private class IngestBase_Test {
    /** Concrete subclass whose ingest() succeeds, to cover the happy path. */
    private class NoopIngest extends IngestBase {
        public NoopIngest(Id scanRunId) {
            super(scanRunId);
        }
        protected override void ingest(QueueableContext context) {
            // no-op: exercises execute() -> ingest() without error
        }
    }

    /** Concrete subclass whose ingest() throws, to cover the error wrapper. */
    private class ThrowingIngest extends IngestBase {
        public ThrowingIngest(Id scanRunId) {
            super(scanRunId);
        }
        protected override void ingest(QueueableContext context) {
            throw new CalloutException('boom');
        }
    }

    @IsTest
    static void execute_success_invokesIngest() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();

        Test.startTest();
        new NoopIngest(run.Id).execute(null);
        Test.stopTest();

        // No failure should have been recorded.
        SecOps_Scan_Run__c reloaded = [SELECT Status__c FROM SecOps_Scan_Run__c WHERE Id = :run.Id];
        System.assertNotEquals('Failed', reloaded.Status__c, 'Successful ingest should not mark the run failed');
    }

    @IsTest
    static void execute_error_recordsFailureOnScanRun() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();

        Test.startTest();
        new ThrowingIngest(run.Id).execute(null);
        Test.stopTest();

        SecOps_Scan_Run__c reloaded = [SELECT Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :run.Id];
        System.assert(
            reloaded.Error_Log__c != null && reloaded.Error_Log__c.contains('boom'),
            'handleError should record the thrown message on the run'
        );
    }
}
