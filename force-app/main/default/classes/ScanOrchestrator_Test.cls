@IsTest
private class ScanOrchestrator_Test {
    @IsTest
    static void enqueueOrchestrator_persistsScanRun() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new ScanOrchestrator(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Id, Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertNotEquals(null, run, 'Scan_Run should still exist after orchestrator runs');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('LoginHistory'),
            'Orchestrator should log the LoginHistory phase entry'
        );
    }
}
