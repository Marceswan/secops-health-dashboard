@IsTest
private class SecOpsScheduledRunner_Test {
    @IsTest
    static void execute_createsScheduledRun() {
        Integer before = [SELECT COUNT() FROM SecOps_Scan_Run__c WHERE Run_Type__c = 'Scheduled'];

        Test.startTest();
        String cron = '0 0 3 * * ?';
        System.schedule('SecOps Scheduled Runner Test', cron, new SecOpsScheduledRunner());
        Test.stopTest();

        // Scheduling a job does not fire execute() in this test path. Invoke the
        // schedulable directly to assert the side effect (Scan_Run creation).
        new SecOpsScheduledRunner().execute(null);

        List<SecOps_Scan_Run__c> created = [
            SELECT Id, Run_Type__c, Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Run_Type__c = 'Scheduled'
        ];
        System.assert(created.size() > before, 'Schedulable execute should create a Scheduled Scan_Run');

        SecOps_Scan_Run__c run = created[created.size() - 1];
        System.assertEquals('Scheduled', run.Run_Type__c, 'Run_Type__c should be Scheduled');
        System.assertEquals('Running', run.Status__c, 'Status should be Running until orchestrator completes');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('window start'),
            'Schedulable should append the window start to the run log'
        );
    }

    @IsTest
    static void execute_usesLastCompletedRunWindow() {
        Datetime priorCompletion = Datetime.now().addHours(-3);
        SecOps_Scan_Run__c prior = new SecOps_Scan_Run__c(
            Run_Type__c = 'Scheduled',
            Status__c = 'Complete',
            Started_At__c = priorCompletion.addMinutes(-5),
            Completed_At__c = priorCompletion,
            Signals_Evaluated__c = 0
        );
        insert prior;

        Test.startTest();
        new SecOpsScheduledRunner().execute(null);
        Test.stopTest();

        List<SecOps_Scan_Run__c> runs = [
            SELECT Id, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Status__c = 'Running' AND Run_Type__c = 'Scheduled'
            ORDER BY CreatedDate DESC
            LIMIT 1
        ];
        System.assertEquals(1, runs.size(), 'A new running scheduled scan should exist');
        System.assert(
            runs[0].Error_Log__c.contains(priorCompletion.formatGmt('yyyy-MM-dd HH:mm:ss')),
            'Window start log line should reflect prior completion time'
        );
    }
}
