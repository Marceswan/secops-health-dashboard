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

        return evaluateRules(
            scanRunId,
            rules,
            caps.hasEventLogFile,
            caps.hasRealTimeEventMonitoring,
            windowStart,
            windowEnd
        );
    }

    /**
     * Execute a supplied set of rule configurations. Separated from evaluateAll so
     * it can be exercised in tests with in-memory Detection_Rule__mdt records,
     * since CMDT rows cannot be created via DML in tests and may be deployed
     * separately from this code.
     */
    @TestVisible
    private static Integer evaluateRules(
        Id scanRunId,
        List<Detection_Rule__mdt> rules,
        Boolean hasEventLogFile,
        Boolean hasRealTimeEventMonitoring,
        Datetime windowStart,
        Datetime windowEnd
    ) {
        List<Security_Finding__c> aggregated = new List<Security_Finding__c>();
        for (Detection_Rule__mdt rule : rules) {
            try {
                if (!isCapabilitySatisfied(rule, hasEventLogFile, hasRealTimeEventMonitoring)) {
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
                    hasEventLogFile,
                    hasRealTimeEventMonitoring,
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
     * the matching capability flag is true.
     */
    private static Boolean isCapabilitySatisfied(
        Detection_Rule__mdt rule,
        Boolean hasEventLogFile,
        Boolean hasRealTimeEventMonitoring
    ) {
        String cap = rule.Required_Capability__c;
        if (cap == null || String.isBlank(cap)) {
            return true;
        }
        if ('EventLogFile'.equalsIgnoreCase(cap)) {
            return hasEventLogFile;
        }
        if ('RealTimeEventMonitoring'.equalsIgnoreCase(cap)) {
            return hasRealTimeEventMonitoring;
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
