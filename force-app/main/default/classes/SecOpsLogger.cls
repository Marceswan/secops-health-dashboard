public class SecOpsLogger {
    public static void log(Id scanRunId, String message) {
        ScanRunService.appendLog(scanRunId, message);
    }
}
