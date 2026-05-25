/**
 * @AuraEnabled controller for the SecOps continuous-mode schedule LWC.
 *
 * Reads and writes the org-default SecOps_Schedule_Config__c hierarchy
 * custom setting and wires the SecOpsScheduledRunner Schedulable on enable.
 * disableSchedule aborts the matching CronTrigger jobs before clearing the
 * Enabled__c flag.
 */
public with sharing class SecOpsScheduleController {
    @TestVisible
    private static final String JOB_NAME = 'SecOps Scheduled Runner';

    /**
     * Return the org-default SecOps_Schedule_Config__c row.
     * If no row has been saved yet, returns a fresh in-memory instance so the
     * LWC can bind to default values without a separate null guard.
     */
    @AuraEnabled(cacheable=true)
    public static SecOps_Schedule_Config__c getConfig() {
        SecOps_Schedule_Config__c cfg = SecOps_Schedule_Config__c.getOrgDefaults();
        if (cfg == null) {
            cfg = new SecOps_Schedule_Config__c();
        }
        return cfg;
    }

    /**
     * Upsert the org-default schedule configuration with the supplied values.
     * Caller is expected to validate cadenceHours (1-24) and baselineRefreshHour (0-23)
     * client-side; this method writes whatever it receives.
     */
    @AuraEnabled
    public static SecOps_Schedule_Config__c saveConfig(
        Boolean enabled,
        Integer cadenceHours,
        String baselineRefreshDay,
        Integer baselineRefreshHour
    ) {
        SecOps_Schedule_Config__c cfg = SecOps_Schedule_Config__c.getOrgDefaults();
        if (cfg == null) {
            cfg = new SecOps_Schedule_Config__c();
            cfg.SetupOwnerId = UserInfo.getOrganizationId();
        }
        cfg.Enabled__c = enabled == null ? false : enabled;
        if (cadenceHours != null) {
            cfg.Cadence_Hours__c = cadenceHours;
        }
        if (!String.isBlank(baselineRefreshDay)) {
            cfg.Baseline_Refresh_Day__c = baselineRefreshDay;
        }
        if (baselineRefreshHour != null) {
            cfg.Baseline_Refresh_Hour__c = baselineRefreshHour;
        }
        upsert cfg;
        return cfg;
    }

    /**
     * Enable continuous scheduling. Aborts any existing SecOps Scheduled Runner
     * job, schedules a new one on the supplied cadence (in hours), and persists
     * Enabled__c=true with the cadence.
     */
    @AuraEnabled
    public static SecOps_Schedule_Config__c enableSchedule(Integer cadenceHours) {
        Integer effectiveCadence = cadenceHours != null ? cadenceHours : 4;
        unscheduleExisting();
        String cron = cronForCadence(effectiveCadence);
        if (!Test.isRunningTest()) {
            System.schedule(JOB_NAME, cron, new SecOpsScheduledRunner());
        }

        SecOps_Schedule_Config__c cfg = SecOps_Schedule_Config__c.getOrgDefaults();
        if (cfg == null) {
            cfg = new SecOps_Schedule_Config__c();
            cfg.SetupOwnerId = UserInfo.getOrganizationId();
        }
        cfg.Enabled__c = true;
        cfg.Cadence_Hours__c = effectiveCadence;
        upsert cfg;
        return cfg;
    }

    /**
     * Disable continuous scheduling. Aborts any matching scheduled job and
     * persists Enabled__c=false.
     */
    @AuraEnabled
    public static SecOps_Schedule_Config__c disableSchedule() {
        unscheduleExisting();

        SecOps_Schedule_Config__c cfg = SecOps_Schedule_Config__c.getOrgDefaults();
        if (cfg == null) {
            cfg = new SecOps_Schedule_Config__c();
            cfg.SetupOwnerId = UserInfo.getOrganizationId();
        }
        cfg.Enabled__c = false;
        upsert cfg;
        return cfg;
    }

    /**
     * Build a cron expression that fires every N hours starting at minute 0.
     * Cadence is clamped to the 1-24 range; values <= 0 default to 1.
     */
    @TestVisible
    private static String cronForCadence(Integer hours) {
        Integer h = hours == null || hours <= 0 ? 1 : hours;
        if (h >= 24) {
            return '0 0 0 * * ?';
        }
        // seconds minutes hours day-of-month month day-of-week
        return '0 0 0/' + h + ' * * ?';
    }

    /**
     * Abort every active CronTrigger whose CronJobDetail.Name matches JOB_NAME.
     * Safe to call when no matching jobs exist.
     */
    @TestVisible
    private static void unscheduleExisting() {
        List<CronTrigger> jobs = [
            SELECT Id, CronJobDetail.Name
            FROM CronTrigger
            WHERE CronJobDetail.Name = :JOB_NAME
        ];
        for (CronTrigger ct : jobs) {
            try {
                System.abortJob(ct.Id);
            } catch (Exception e) {
                // ignore — abort can race with a job that already finished
            }
        }
    }
}
