/**
 * Contract every detection rule implements.
 * Rules are pluggable, stateless evaluators that read from a DetectionContext
 * and emit Security_Finding__c records.
 */
public interface DetectionRule {
    /**
     * Stable developer name matching a Detection_Rule__mdt record.
     */
    String getDeveloperName();

    /**
     * Returns true if this rule should execute given the org's current capabilities
     * and the metadata configuration in DetectionContext.
     */
    Boolean isApplicable(DetectionContext ctx);

    /**
     * Evaluate the rule. Implementations should NOT perform DML directly;
     * they return findings for the caller to insert in bulk.
     */
    List<Security_Finding__c> evaluate(DetectionContext ctx);
}
