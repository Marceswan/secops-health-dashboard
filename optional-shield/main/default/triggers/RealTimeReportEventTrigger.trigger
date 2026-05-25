trigger RealTimeReportEventTrigger on ReportEventStream(after insert) {
    RealTimeEventStreamHandler.handleReportEvents(Trigger.new);
}
