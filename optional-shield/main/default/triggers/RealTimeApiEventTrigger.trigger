trigger RealTimeApiEventTrigger on ApiEventStream(after insert) {
    RealTimeEventStreamHandler.handleApiEvents(Trigger.new);
}
