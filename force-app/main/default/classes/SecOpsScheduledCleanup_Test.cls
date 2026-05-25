@IsTest
private class SecOpsScheduledCleanup_Test {
    @IsTest
    static void schedule_runsWithoutError() {
        String cron = '0 0 3 * * ?';
        Test.startTest();
        System.schedule('SecOps Cleanup Test', cron, new SecOpsScheduledCleanup());
        Test.stopTest();
        System.assert(true, 'Schedulable installed without exception');
    }
}
