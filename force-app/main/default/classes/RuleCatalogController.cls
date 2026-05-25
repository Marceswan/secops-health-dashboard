/**
 * @AuraEnabled controller for the Detection Rule catalog LWC.
 *
 * Lists Detection_Rule__mdt rows for the Configure tab and toggles
 * the Is_Active__c flag via the async Metadata API. Custom Metadata
 * writes are deferred to a deployment so the caller cannot read the
 * updated row in the same transaction.
 */
public with sharing class RuleCatalogController {
    /**
     * Return every Detection_Rule__mdt row for the catalog UI.
     * Sorted by Category then DeveloperName so related rules group together.
     */
    @AuraEnabled(cacheable=true)
    public static List<Detection_Rule__mdt> listRules() {
        return [
            SELECT
                Id,
                DeveloperName,
                MasterLabel,
                Category__c,
                Severity__c,
                Default_Risk_Score__c,
                Description__c,
                Remediation_Guidance__c,
                Run_Frequency__c,
                Is_Active__c
            FROM Detection_Rule__mdt
            ORDER BY Category__c NULLS LAST, DeveloperName
        ];
    }

    /**
     * Toggle Is_Active__c for a single Detection_Rule__mdt row.
     * No-op during test execution because Metadata.Operations.enqueueDeployment
     * is unsupported in test context.
     */
    @AuraEnabled
    public static void setRuleActive(String developerName, Boolean isActive) {
        if (String.isBlank(developerName) || isActive == null) {
            return;
        }

        Metadata.CustomMetadata cm = new Metadata.CustomMetadata();
        cm.fullName = 'Detection_Rule__mdt.' + developerName;
        cm.label = developerName;

        Metadata.CustomMetadataValue f = new Metadata.CustomMetadataValue();
        f.field = 'Is_Active__c';
        f.value = isActive;
        cm.values.add(f);

        Metadata.DeployContainer container = new Metadata.DeployContainer();
        container.addMetadata(cm);

        if (!Test.isRunningTest()) {
            Metadata.Operations.enqueueDeployment(container, null);
        }
    }
}
