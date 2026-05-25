/**
 * Controller for the SecOps engagement summary PDF (Visualforce, renderAs=pdf).
 *
 * Each getter is computed lazily on first access so the page render only pays for
 * the queries it actually displays. All getters guarantee non-null primitives or
 * empty collections to keep the PDF template tolerant.
 */
public with sharing class EngagementSummaryPdfController {
    /** Rendered timestamp for the page header. */
    public String getGeneratedDate() {
        return Datetime.now().format();
    }

    /** Org name from the Organization table. */
    public String getOrgName() {
        List<Organization> orgs = [SELECT Name FROM Organization LIMIT 1];
        return orgs.isEmpty() ? '' : orgs[0].Name;
    }

    /** Total open findings (Status in New, Acknowledged). */
    public Integer getTotalFindings() {
        return [
            SELECT COUNT()
            FROM Security_Finding__c
            WHERE Status__c IN ('New', 'Acknowledged')
        ];
    }

    /** Open findings with Severity = Critical. */
    public Integer getCriticalCount() {
        return [
            SELECT COUNT()
            FROM Security_Finding__c
            WHERE Status__c IN ('New', 'Acknowledged') AND Severity__c = 'Critical'
        ];
    }

    /** Open findings with Severity = High. */
    public Integer getHighCount() {
        return [
            SELECT COUNT()
            FROM Security_Finding__c
            WHERE Status__c IN ('New', 'Acknowledged') AND Severity__c = 'High'
        ];
    }

    /** Total OAuth apps tracked in inventory. */
    public Integer getAppCount() {
        return [SELECT COUNT() FROM OAuth_App_Inventory__c];
    }

    /** Top 10 users by finding count, formatted for VF apex:repeat. */
    public List<Map<String, Object>> getTopRisks() {
        return PostureController.getTopRisks('user', 10);
    }
}
