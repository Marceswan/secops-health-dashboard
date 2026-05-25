/**
 * Read-only bundle passed to every detection rule. Holds the run identity,
 * the time window, capability flags discovered at runtime, and the metadata
 * configuration for the rule being executed.
 */
public with sharing class DetectionContext {
    public final Id scanRunId;
    public final Datetime windowStart;
    public final Datetime windowEnd;
    public final Boolean hasEventLogFile;
    public final Boolean hasRealTimeEventMonitoring;
    public final Detection_Rule__mdt ruleConfig;

    public DetectionContext(
        Id scanRunId,
        Datetime windowStart,
        Datetime windowEnd,
        Boolean hasEventLogFile,
        Boolean hasRealTimeEventMonitoring,
        Detection_Rule__mdt ruleConfig
    ) {
        this.scanRunId = scanRunId;
        this.windowStart = windowStart;
        this.windowEnd = windowEnd;
        this.hasEventLogFile = hasEventLogFile;
        this.hasRealTimeEventMonitoring = hasRealTimeEventMonitoring;
        this.ruleConfig = ruleConfig;
    }
}
