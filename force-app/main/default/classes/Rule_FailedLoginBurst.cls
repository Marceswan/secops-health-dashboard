/**
 * Detection rule: flags source IPs producing many failed LoginHistory rows
 * within the last hour. A high concentration of failures from a single
 * source IP is a classic password-spray or brute-force indicator.
 */
public with sharing class Rule_FailedLoginBurst implements DetectionRule {
    /** Minimum failures from one IP in the lookback window to raise a finding. */
    private static final Integer FAILURE_THRESHOLD = 10;
    /** Lookback window in minutes. */
    private static final Integer WINDOW_MINUTES = 60;

    public String getDeveloperName() {
        return 'Failed_Login_Burst';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        Datetime cutoff = Datetime.now().addMinutes(-WINDOW_MINUTES);
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Map<String, List<LoginHistory>> bySrcIp = new Map<String, List<LoginHistory>>();

        for (LoginHistory lh : [
            SELECT Id, UserId, SourceIp, LoginTime, Status
            FROM LoginHistory
            WHERE LoginTime >= :cutoff AND SourceIp != NULL
            LIMIT 50000
        ]) {
            if (lh.Status == 'Success') {
                continue;
            }
            if (!bySrcIp.containsKey(lh.SourceIp)) {
                bySrcIp.put(lh.SourceIp, new List<LoginHistory>());
            }
            bySrcIp.get(lh.SourceIp).add(lh);
        }

        for (String ip : bySrcIp.keySet()) {
            List<LoginHistory> rows = bySrcIp.get(ip);
            if (rows.size() >= FAILURE_THRESHOLD) {
                findings.add(
                    FindingFactory.build(
                        ctx.scanRunId,
                        getDeveloperName(),
                        'Login Anomaly',
                        SecOpsConstants.SEVERITY_MEDIUM,
                        null,
                        null,
                        ip,
                        new Map<String, Object>{
                            'sourceIp' => ip,
                            'failureCount' => rows.size(),
                            'windowMinutes' => WINDOW_MINUTES
                        }
                    )
                );
            }
        }
        return findings;
    }
}
