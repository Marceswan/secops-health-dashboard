/**
 * Centralized builder for Security_Finding__c records produced by detection rules.
 *
 * Rules call build(...) instead of constructing the SObject manually so the
 * shape, default Status, and JSON-serialized source payload stay consistent
 * across every rule. The caller is responsible for inserting the returned
 * record (rules return findings in bulk for DML aggregation).
 */
public with sharing class FindingFactory {
    /**
     * Construct a Security_Finding__c from the canonical rule arguments.
     *
     * @param scanRunId     Parent Scan_Run for this finding (master-detail).
     * @param ruleName      Detection rule developer name (also stored on the finding).
     * @param category      One of the Category__c picklist values.
     * @param severity      One of the Severity__c picklist values.
     * @param subjectUserId Optional User Id the finding is about.
     * @param subjectAppId  Optional OAuth_App_Inventory__c Id the finding is about.
     * @param sourceEventId Required free-text id of the originating signal.
     * @param payload       Structured payload serialized to Source_Event_Json__c.
     */
    public static Security_Finding__c build(
        Id scanRunId,
        String ruleName,
        String category,
        String severity,
        Id subjectUserId,
        Id subjectAppId,
        String sourceEventId,
        Map<String, Object> payload
    ) {
        Security_Finding__c f = new Security_Finding__c();
        f.Scan_Run__c = scanRunId;
        f.Detection_Rule__c = ruleName;
        f.Category__c = category;
        f.Severity__c = severity;
        f.Status__c = SecOpsConstants.STATUS_NEW;
        f.Subject_User__c = subjectUserId;
        f.Subject_App__c = subjectAppId;
        f.Source_Event_Id__c = sourceEventId;
        f.Source_Event_Json__c = payload == null ? null : JSON.serialize(payload);
        f.Risk_Score__c = riskScoreFor(severity);
        return f;
    }

    /**
     * Default risk score mapped from severity. Rules that need a custom score
     * can overwrite Risk_Score__c after calling build().
     */
    private static Integer riskScoreFor(String severity) {
        if (SecOpsConstants.SEVERITY_CRITICAL.equals(severity)) {
            return SecOpsConstants.RISK_CRITICAL;
        }
        if (SecOpsConstants.SEVERITY_HIGH.equals(severity)) {
            return SecOpsConstants.RISK_HIGH;
        }
        if (SecOpsConstants.SEVERITY_MEDIUM.equals(severity)) {
            return SecOpsConstants.RISK_MEDIUM;
        }
        return SecOpsConstants.RISK_LOW;
    }
}
