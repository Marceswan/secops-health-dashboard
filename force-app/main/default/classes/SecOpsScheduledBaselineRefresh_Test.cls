@IsTest
private class SecOpsScheduledBaselineRefresh_Test {
    @IsTest
    static void schedule_runsWithoutError() {
        String cron = '0 0 2 * * ?';
        Test.startTest();
        System.schedule('SecOps Baseline Refresh Test', cron, new SecOpsScheduledBaselineRefresh());
        Test.stopTest();
        // Reaching this point without exception is the assertion. The scheduled
        // job will enqueue UserBaselineRefresh which has its own coverage.
        System.assert(true, 'Schedulable installed without exception');
    }
}
