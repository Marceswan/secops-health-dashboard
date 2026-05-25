@IsTest
private class ScanRunService_Test {
    @IsTest
    static void start_insertsRunningRecord() {
        Test.startTest();
        Id runId = ScanRunService.start('Manual Scan');
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Id, Run_Type__c, Status__c, Started_At__c, Signals_Evaluated__c, Findings_Created__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertEquals('Manual Scan', run.Run_Type__c, 'Run_Type__c should be set');
        System.assertEquals('Running', run.Status__c, 'Status should default to Running');
        System.assertNotEquals(null, run.Started_At__c, 'Started_At__c must be populated');
        System.assertEquals(0, run.Signals_Evaluated__c, 'Signals_Evaluated__c should start at 0');
        System.assertEquals(0, run.Findings_Created__c, 'Findings_Created__c should start at 0');
    }

    @IsTest
    static void complete_setsCompleteWithCounters() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        ScanRunService.complete(runId, 42, 7);
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Status__c, Completed_At__c, Signals_Evaluated__c, Findings_Created__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertEquals('Complete', run.Status__c);
        System.assertNotEquals(null, run.Completed_At__c);
        System.assertEquals(42, run.Signals_Evaluated__c);
        // Findings_Created__c is now a rollup summary populated by inserted
        // Security_Finding__c child records. Since this test does not insert
        // children, the rollup remains 0 regardless of the value passed to
        // complete(). Asserted explicitly to document the behavior change.
        System.assertEquals(0, run.Findings_Created__c);
    }

    @IsTest
    static void fail_setsFailedAndAppendsLog() {
        Id runId = ScanRunService.start('Scheduled');

        Test.startTest();
        ScanRunService.fail(runId, 'simulated failure');
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Status__c, Completed_At__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertEquals('Failed', run.Status__c);
        System.assertNotEquals(null, run.Completed_At__c);
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('simulated failure'),
            'Error log should contain failure message'
        );
    }

    @IsTest
    static void appendLog_addsLineWithoutChangingStatus() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        ScanRunService.appendLog(runId, 'phase started');
        ScanRunService.appendLog(runId, 'phase complete');
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertEquals('Running', run.Status__c, 'appendLog must not change status');
        System.assert(run.Error_Log__c.contains('phase started'), 'first entry retained');
        System.assert(run.Error_Log__c.contains('phase complete'), 'second entry appended');
    }
}
