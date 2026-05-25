/**
 * Schedulable wrapper for UserBaselineRefresh.
 *
 * Schedule nightly via System.schedule(...) or the Schedule_Config__c
 * driver. The class simply enqueues a single Queueable so the heavy
 * lifting happens off the scheduler thread.
 */
public with sharing class SecOpsScheduledBaselineRefresh implements Schedulable {
    public void execute(SchedulableContext sc) {
        System.enqueueJob(new UserBaselineRefresh());
    }
}
