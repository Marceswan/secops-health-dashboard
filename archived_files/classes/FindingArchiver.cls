/**
 * Batchable archiver for resolved Security_Finding__c records.
 *
 * Scope: Findings whose Status__c is Remediated or Dismissed and whose
 * Resolved_At__c is older than 90 days. Each batch copies the source rows
 * into the Security_Finding_Archive__b Big Object via insertImmediate and
 * then deletes the source records so the transactional store stays lean.
 */
public with sharing class FindingArchiver implements Database.Batchable<SObject> {
    @TestVisible
    private static final Integer ARCHIVE_AGE_DAYS = 90;

    public Database.QueryLocator start(Database.BatchableContext bc) {
        Datetime cutoff = Datetime.now().addDays(-ARCHIVE_AGE_DAYS);
        return Database.getQueryLocator(
            [
                SELECT
                    Id,
                    Name,
                    Status__c,
                    Severity__c,
                    Category__c,
                    Detection_Rule__c,
                    Subject_User__c,
                    Subject_App__c,
                    Resolved_At__c,
                    Action_History__c
                FROM Security_Finding__c
                WHERE Status__c IN ('Remediated', 'Dismissed') AND Resolved_At__c != NULL AND Resolved_At__c < :cutoff
            ]
        );
    }

    public void execute(Database.BatchableContext bc, List<Security_Finding__c> scope) {
        if (scope == null || scope.isEmpty()) {
            return;
        }
        Datetime now = Datetime.now();
        List<Security_Finding_Archive__b> archives = new List<Security_Finding_Archive__b>();
        for (Security_Finding__c f : scope) {
            Security_Finding_Archive__b row = new Security_Finding_Archive__b();
            row.Archived_At__c = now;
            row.Subject_User_Id__c = f.Subject_User__c != null ? String.valueOf(f.Subject_User__c) : null;
            row.Finding_Number__c = f.Name;
            row.Status__c = f.Status__c;
            row.Severity__c = f.Severity__c;
            row.Category__c = f.Category__c;
            row.Detection_Rule__c = f.Detection_Rule__c;
            row.Subject_App_Id__c = f.Subject_App__c != null ? String.valueOf(f.Subject_App__c) : null;
            row.Resolved_At__c = f.Resolved_At__c;
            row.Action_History__c = f.Action_History__c;
            archives.add(row);
        }
        if (!archives.isEmpty()) {
            Database.insertImmediate(archives);
        }
        delete scope;
    }

    public void finish(Database.BatchableContext bc) {
        // no-op
    }
}
