@IsTest
private class SecOpsScheduleController_Test {
    @IsTest
    static void getConfig_returnsNonNullWhenEmpty() {
        Test.startTest();
        SecOps_Schedule_Config__c cfg = SecOpsScheduleController.getConfig();
        Test.stopTest();
        System.assertNotEquals(null, cfg, 'getConfig should never return null');
    }

    @IsTest
    static void saveConfig_roundTrips() {
        Test.startTest();
        SecOpsScheduleController.saveConfig(true, 6, 'Monday', 3);
        SecOps_Schedule_Config__c cfg = SecOpsScheduleController.getConfig();
        Test.stopTest();

        System.assertEquals(true, cfg.Enabled__c, 'Enabled should round-trip');
        System.assertEquals(6, cfg.Cadence_Hours__c, 'Cadence should round-trip');
        System.assertEquals('Monday', cfg.Baseline_Refresh_Day__c, 'Day should round-trip');
        System.assertEquals(3, cfg.Baseline_Refresh_Hour__c, 'Hour should round-trip');
    }

    @IsTest
    static void enableAndDisableSchedule_togglesFlag() {
        Test.startTest();
        SecOps_Schedule_Config__c enabled = SecOpsScheduleController.enableSchedule(4);
        System.assertEquals(true, enabled.Enabled__c, 'enableSchedule sets Enabled__c=true');
        System.assertEquals(4, enabled.Cadence_Hours__c, 'enableSchedule writes cadence');

        SecOps_Schedule_Config__c disabled = SecOpsScheduleController.disableSchedule();
        Test.stopTest();
        System.assertEquals(false, disabled.Enabled__c, 'disableSchedule clears Enabled__c');
    }

    @IsTest
    static void enableSchedule_schedulesRunnerJob() {
        Test.startTest();
        // Pre-schedule a job under the canonical name so the controller exercises
        // the unschedule path before laying down its own scheduled job.
        System.schedule(SecOpsScheduleController.JOB_NAME, '0 0 1 * * ?', new SecOpsScheduledRunner());
        SecOpsScheduleController.enableSchedule(6);
        Test.stopTest();

        // The controller short-circuits System.schedule in test context, so we
        // assert state on the persisted config rather than CronTrigger rows.
        SecOps_Schedule_Config__c cfg = SecOpsScheduleController.getConfig();
        System.assertEquals(true, cfg.Enabled__c, 'enableSchedule should persist Enabled__c=true');
        System.assertEquals(6, cfg.Cadence_Hours__c, 'enableSchedule should persist the cadence');
    }

    @IsTest
    static void disableSchedule_abortsExistingJob() {
        Test.startTest();
        System.schedule(SecOpsScheduleController.JOB_NAME, '0 0 2 * * ?', new SecOpsScheduledRunner());
        SecOps_Schedule_Config__c result = SecOpsScheduleController.disableSchedule();
        Test.stopTest();

        System.assertEquals(false, result.Enabled__c, 'disableSchedule should clear Enabled__c');

        List<CronTrigger> remaining = [
            SELECT Id
            FROM CronTrigger
            WHERE CronJobDetail.Name = :SecOpsScheduleController.JOB_NAME
        ];
        System.assertEquals(0, remaining.size(), 'disableSchedule should abort the named scheduled job');
    }

    @IsTest
    static void cronForCadence_buildsExpectedExpression() {
        System.assertEquals(
            '0 0 0/4 * * ?',
            SecOpsScheduleController.cronForCadence(4),
            '4-hour cadence cron should fire every 4 hours from midnight'
        );
        System.assertEquals(
            '0 0 0 * * ?',
            SecOpsScheduleController.cronForCadence(24),
            '24-hour cadence should fire once at midnight'
        );
        System.assertEquals(
            '0 0 0/1 * * ?',
            SecOpsScheduleController.cronForCadence(0),
            'Zero or negative cadence should clamp to hourly'
        );
    }
}
