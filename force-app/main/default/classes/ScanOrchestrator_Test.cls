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

    /**
     * Drive each phase of the orchestrator directly. In test context the ingest
     * phases only log (enqueue is suppressed); DETECTION runs the engine and
     * COMPLETE finalizes the run. A bogus phase routes to the failure path.
     */
    @IsTest
    static void execute_walksEveryPhase() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        for (
            String phase : new List<String>{
                'LoginHistory',
                'OAuthInventory',
                'SetupAudit',
                'PermissionChange',
                'EventLogFile',
                'DETECTION'
            }
        ) {
            new ScanOrchestrator(runId, phase).execute(null);
        }
        new ScanOrchestrator(runId, 'BOGUS_PHASE').execute(null);
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Id, Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assert(run.Error_Log__c != null, 'Phase walk should have appended log entries');
        System.assert(
            run.Error_Log__c.contains('unknown phase'),
            'Bogus phase should route through the failure path'
        );
    }

    @IsTest
    static void execute_completePhase_finalizesRun() {
        Id runId = ScanRunService.start('Scheduled');

        Test.startTest();
        new ScanOrchestrator(runId, 'COMPLETE').execute(null);
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c, Completed_At__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertEquals('Complete', run.Status__c, 'COMPLETE phase should finalize the run');
        System.assertNotEquals(null, run.Completed_At__c, 'COMPLETE should stamp Completed_At__c');
    }
}
