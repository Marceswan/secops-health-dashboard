/**
 * Sample Transaction Security Policy hook for the SecOps Health Dashboard.
 *
 * SHIPPING NOTES — READ BEFORE DEPLOYING
 * ----------------------------------------------------------------------------
 * - This class implements TxnSecurity.AsyncCondition, which is a Shield /
 *   Event Monitoring interface. Orgs without Shield will fail to compile this
 *   class with "Type not found". For that reason, this file lives in the
 *   sibling `optional-shield/` package directory and is NOT part of the default
 *   `force-app` package deployed by `manifest/package.xml`.
 *
 * - To enable for a customer with Shield:
 *     1. Add `optional-shield` as a default package directory in
 *        sfdx-project.json (or deploy this file directly with `sf project
 *        deploy start --source-dir optional-shield`).
 *     2. In Setup > Transaction Security Policies, create a new policy:
 *          - Type: API Anomaly (or whichever real-time event applies)
 *          - Apex Class: TransactionSecurityHookExample
 *          - Action: Notify / Block (per customer policy)
 *     3. Activate the policy.
 *
 * - The body below is a stub: it returns false (does NOT block any event).
 *   Edit the evaluate() method to implement customer-specific risk logic
 *   (e.g. cross-reference Security_Finding__c severity, geo-velocity, etc.).
 *
 * - No paired test class ships in `optional-shield/`. Because the TxnSecurity
 *   namespace is gated by Shield licensing, a coverage harness only compiles
 *   in an org that has Shield enabled. Write coverage in the customer's org
 *   after enabling.
 */
global class TransactionSecurityHookExample implements TxnSecurity.AsyncCondition {
    /**
     * Evaluate a Real-Time Event Monitoring event. Returning true triggers the
     * configured policy action (notify / block). The default stub returns false
     * so deploying this class never produces side effects.
     */
    global Boolean evaluate(TxnSecurity.Event txnEvent) {
        // Customer-specific risk logic goes here.
        // Example shape (commented out — uncomment and adapt per engagement):
        // if (txnEvent != null && txnEvent.entityId != null) {
        //     Integer recent = [
        //         SELECT COUNT()
        //         FROM Security_Finding__c
        //         WHERE User__c = :txnEvent.userId
        //           AND Severity__c = 'High'
        //           AND CreatedDate = LAST_N_HOURS:24
        //     ];
        //     return recent > 0;
        // }
        return false;
    }
}
