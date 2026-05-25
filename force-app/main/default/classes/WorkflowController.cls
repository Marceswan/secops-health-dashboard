/**
 * Workflow actions for Security_Finding__c records.
 *
 * Powers the SecOps dashboard finding detail and bulk action bar LWCs.
 * Each action updates the finding Status__c, appends an entry to
 * Action_History__c, and inserts a paired Action_Audit__c row for the
 * permanent audit trail.
 *
 * Master-detail constraint: Security_Finding__c is a master-detail child of
 * SecOps_Scan_Run__c, so OwnerId is not addressable on the finding (it is
 * inherited from the parent). assignTo() therefore does NOT transfer
 * ownership - it only posts a FeedItem @-mention so the assignee is notified.
 */
public with sharing class WorkflowController {
    /** DTO returned to LWC describing the post-action state of a finding. */
    public class ActionResult {
        @AuraEnabled
        public Id findingId;
        @AuraEnabled
        public String status;
        @AuraEnabled
        public Datetime resolvedAt;
    }

    /**
     * Move a single finding from New -> Acknowledged.
     */
    @AuraEnabled
    public static ActionResult acknowledge(Id findingId) {
        if (findingId == null) {
            throw new AuraHandledException('findingId is required');
        }
        List<ActionResult> results = acknowledgeBulk(new List<Id>{ findingId });
        return results.isEmpty() ? null : results[0];
    }

    /**
     * Bulk-acknowledge a list of findings. Used by secopsBulkActionBar.
     */
    @AuraEnabled
    public static List<ActionResult> acknowledgeBulk(List<Id> findingIds) {
        return transitionMany(findingIds, SecOpsConstants.STATUS_ACKNOWLEDGED, null, 'Acknowledge');
    }

    /**
     * Dismiss a single finding with an explanatory reason.
     */
    @AuraEnabled
    public static ActionResult dismiss(Id findingId, String reason) {
        if (findingId == null) {
            throw new AuraHandledException('findingId is required');
        }
        List<ActionResult> results = dismissBulk(new List<Id>{ findingId }, reason);
        return results.isEmpty() ? null : results[0];
    }

    /**
     * Bulk-dismiss findings with the same reason. Used by secopsBulkActionBar.
     */
    @AuraEnabled
    public static List<ActionResult> dismissBulk(List<Id> findingIds, String reason) {
        return transitionMany(findingIds, SecOpsConstants.STATUS_DISMISSED, reason, 'Dismiss');
    }

    /**
     * Mark a finding Remediated. Sets Resolved_At__c and Resolved_By__c.
     */
    @AuraEnabled
    public static ActionResult markRemediated(Id findingId) {
        if (findingId == null) {
            throw new AuraHandledException('findingId is required');
        }
        List<ActionResult> results = transitionMany(
            new List<Id>{ findingId },
            SecOpsConstants.STATUS_REMEDIATED,
            null,
            'Remediate'
        );
        return results.isEmpty() ? null : results[0];
    }

    /**
     * Notify a user about a finding via a FeedItem @-mention.
     *
     * Master-detail constraint: Security_Finding__c.OwnerId is inherited from
     * Scan_Run__c and cannot be written directly. This method intentionally
     * does NOT transfer ownership - it only posts a chatter notification so
     * the target user is alerted that the finding needs their attention.
     *
     * @param findingId Finding to post against.
     * @param userId    User to @-mention.
     */
    @AuraEnabled
    public static Id assignTo(Id findingId, Id userId) {
        if (findingId == null || userId == null) {
            throw new AuraHandledException('findingId and userId are required');
        }
        try {
            // No OwnerId update: Security_Finding__c is master-detail child of Scan_Run__c.
            FeedItem post = new FeedItem();
            post.ParentId = findingId;
            post.Body = '@[' + userId + '] please review this finding.';
            post.Type = 'TextPost';
            insert post;
            return post.Id;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    /**
     * Core transition routine: applies the new status to every finding in the
     * input list, appends an Action_History__c entry, and writes one
     * Action_Audit__c row per finding. All DML is bulk-safe.
     */
    private static List<ActionResult> transitionMany(
        List<Id> findingIds,
        String newStatus,
        String reason,
        String actionType
    ) {
        if (findingIds == null || findingIds.isEmpty()) {
            return new List<ActionResult>();
        }
        try {
            List<Security_Finding__c> findings = [
                SELECT Id, Status__c, Action_History__c, Dismissal_Reason__c, Resolved_At__c, Resolved_By__c
                FROM Security_Finding__c
                WHERE Id IN :findingIds
                WITH SECURITY_ENFORCED
            ];

            Datetime now = Datetime.now();
            Id actorId = UserInfo.getUserId();
            String stamp = now.format('yyyy-MM-dd HH:mm:ss') + ' ' + actorId + ' ' + actionType;

            List<Action_Audit__c> audits = new List<Action_Audit__c>();
            List<ActionResult> results = new List<ActionResult>();

            for (Security_Finding__c f : findings) {
                f.Status__c = newStatus;
                String entry = stamp;
                if (String.isNotBlank(reason)) {
                    entry += ': ' + reason;
                    f.Dismissal_Reason__c = reason;
                }
                f.Action_History__c = (String.isBlank(f.Action_History__c) ? '' : f.Action_History__c + '\n') + entry;
                if (
                    SecOpsConstants.STATUS_REMEDIATED.equals(newStatus) ||
                    SecOpsConstants.STATUS_DISMISSED.equals(newStatus)
                ) {
                    f.Resolved_At__c = now;
                    f.Resolved_By__c = actorId;
                }

                audits.add(buildAudit(f.Id, actionType, actorId, now, reason));

                ActionResult r = new ActionResult();
                r.findingId = f.Id;
                r.status = newStatus;
                r.resolvedAt = f.Resolved_At__c;
                results.add(r);
            }

            update findings;
            logAuditBatch(audits);
            return results;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    /**
     * Build an Action_Audit__c row matching the restricted picklist values on
     * the object. Action_Type__c is one of: Acknowledge, Dismiss, Remediate.
     */
    private static Action_Audit__c buildAudit(
        Id findingId,
        String actionType,
        Id actorId,
        Datetime actionAt,
        String reason
    ) {
        Action_Audit__c a = new Action_Audit__c();
        a.Finding__c = findingId;
        a.Action_Type__c = actionType;
        a.Actor__c = actorId;
        a.Action_Time__c = actionAt;
        a.Target_Id__c = findingId;
        Map<String, Object> params = new Map<String, Object>();
        if (String.isNotBlank(reason)) {
            params.put('reason', reason);
        }
        a.Parameters_Json__c = JSON.serialize(params);
        a.Result__c = 'Success';
        return a;
    }

    /**
     * Insert a list of audit rows. Surfaced as @TestVisible-equivalent helper
     * so tests can verify audit counts after each action.
     */
    private static void logAuditBatch(List<Action_Audit__c> audits) {
        if (audits == null || audits.isEmpty()) {
            return;
        }
        insert audits;
    }
}
