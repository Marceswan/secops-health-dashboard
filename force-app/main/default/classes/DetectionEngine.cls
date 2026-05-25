/**
 * Orchestrates the execution of all active Detection_Rule__mdt rules for a
 * Scan_Run. Reads rule metadata, instantiates each Apex_Class__c dynamically,
 * checks capability gating, and inserts the resulting findings in bulk.
 *
 * Rules return Security_Finding__c records without performing DML so this
 * class can aggregate, deduplicate by Composite_Key__c, and apply a single
 * Database.insert call.
 */
public with sharing class DetectionEngine {
    /**
     * Run every active detection rule against the given Scan_Run.
     *
     * @param scanRunId Parent Scan_Run that owns the findings created here.
     * @return Number of findings successfully inserted.
     */
    public static Integer evaluateAll(Id scanRunId) {
        if (scanRunId == null) {
            return 0;
        }

        CapabilityProbe.ProbeResult caps = CapabilityProbe.runNow();
        Datetime windowEnd = Datetime.now();
        Datetime windowStart = windowEnd.addHours(-SecOpsConstants.DEFAULT_LOOKBACK_HOURS);

        List<Detection_Rule__mdt> rules = [
            SELECT
                DeveloperName,
                Apex_Class__c,
                Category__c,
                Severity__c,
                Required_Capability__c,
                Is_Active__c,
                Default_Risk_Score__c,
                Run_Frequency__c,
                Description__c,
                Remediation_Guidance__c
            FROM Detection_Rule__mdt
            WHERE Is_Active__c = TRUE
        ];

        List<Security_Finding__c> aggregated = new List<Security_Finding__c>();
        for (Detection_Rule__mdt rule : rules) {
            try {
                if (!isCapabilitySatisfied(rule, caps)) {
                    ScanRunService.appendLog(
                        scanRunId,
                        'DetectionEngine: skipping ' + rule.DeveloperName + ' (capability gate)'
                    );
                    continue;
                }
                DetectionRule impl = instantiateRule(rule.Apex_Class__c);
                if (impl == null) {
                    ScanRunService.appendLog(scanRunId, 'DetectionEngine: could not instantiate ' + rule.Apex_Class__c);
                    continue;
                }
                DetectionContext ctx = new DetectionContext(
                    scanRunId,
                    windowStart,
                    windowEnd,
                    caps.hasEventLogFile,
                    caps.hasRealTimeEventMonitoring,
                    rule
                );
                List<Security_Finding__c> produced = impl.evaluate(ctx);
                if (produced != null && !produced.isEmpty()) {
                    aggregated.addAll(produced);
                }
                ScanRunService.appendLog(
                    scanRunId,
                    'DetectionEngine: ' +
                        rule.DeveloperName +
                        ' produced ' +
                        (produced == null ? 0 : produced.size()) +
                        ' findings'
                );
            } catch (Exception e) {
                ScanRunService.appendLog(
                    scanRunId,
                    'DetectionEngine: ' + rule.DeveloperName + ' failed: ' + e.getMessage()
                );
            }
        }

        return insertDeduped(aggregated);
    }

    /**
     * Capability gating: a rule with Required_Capability__c set only runs when
     * the matching capability flag in the probe result is true.
     */
    private static Boolean isCapabilitySatisfied(Detection_Rule__mdt rule, CapabilityProbe.ProbeResult caps) {
        String cap = rule.Required_Capability__c;
        if (cap == null || String.isBlank(cap)) {
            return true;
        }
        if ('EventLogFile'.equalsIgnoreCase(cap)) {
            return caps.hasEventLogFile;
        }
        if ('RealTimeEventMonitoring'.equalsIgnoreCase(cap)) {
            return caps.hasRealTimeEventMonitoring;
        }
        return true;
    }

    /**
     * Dynamically instantiate the DetectionRule implementation by class name.
     * Returns null when the class is not found or does not implement DetectionRule.
     */
    private static DetectionRule instantiateRule(String className) {
        if (String.isBlank(className)) {
            return null;
        }
        Type t = Type.forName(className);
        if (t == null) {
            return null;
        }
        Object instance = t.newInstance();
        if (!(instance instanceof DetectionRule)) {
            return null;
        }
        return (DetectionRule) instance;
    }

    /**
     * Insert findings tolerantly: rows that collide on Composite_Key__c are
     * dropped by the platform; we count only the successful inserts.
     */
    private static Integer insertDeduped(List<Security_Finding__c> findings) {
        if (findings == null || findings.isEmpty()) {
            return 0;
        }
        Database.SaveResult[] results = Database.insert(findings, false);
        Integer inserted = 0;
        for (Database.SaveResult sr : results) {
            if (sr.isSuccess()) {
                inserted++;
            }
        }
        return inserted;
    }
}
