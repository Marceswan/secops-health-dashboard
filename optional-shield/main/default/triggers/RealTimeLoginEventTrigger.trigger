trigger RealTimeLoginEventTrigger on LoginEventStream(after insert) {
    RealTimeEventStreamHandler.handleLoginEvents(Trigger.new);
}
