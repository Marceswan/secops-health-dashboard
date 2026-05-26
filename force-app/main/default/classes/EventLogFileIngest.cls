/**
 * Ingest phase that pulls yesterday's EventLogFile rows (a Shield / Event
 * Monitoring add-on) and stages them as Security_Event__c records for
 * downstream detection.
 *
 * This phase is conditional on the org licensing EventLogFile. CapabilityProbe
 * reports hasEventLogFile=false on orgs without the add-on, in which case this
 * ingest logs a "skipped" line and returns without DML.
 *
 * Phase transitions are owned by ScanOrchestrator: this class only does its
 * own work and lets the orchestrator advance to DETECTION.
 *
 * Governor footprint:
 *   - At most 100 EventLogFile headers per run (LIMIT 100).
 *   - At most 5,000 parsed rows per file (cap enforced in code).
 *   - Database.insert(..., false) so duplicate Composite_Key__c rows don't
 *     fail the whole batch.
 */
public with sharing class EventLogFileIngest extends IngestBase implements Database.AllowsCallouts {
    private static final Integer FILE_LIMIT = 100;
    private static final Integer ROW_CAP_PER_FILE = 5000;
    private static final Integer SOURCE_JSON_MAX = 32768;

    /** Picklist values on Security_Event__c.Event_Type__c that we map into. */
    private static final Set<String> SUPPORTED_EVENT_TYPES = new Set<String>{
        'Login',
        'LoginAs',
        'ReportExport',
        'ApiTotalUsage',
        'BulkApi',
        'RestApi',
        'URI'
    };

    private Datetime windowStartOverride;

    public EventLogFileIngest(Id scanRunId) {
        super(scanRunId);
        this.windowStartOverride = null;
    }

    public EventLogFileIngest(Id scanRunId, Datetime windowStart) {
        super(scanRunId);
        this.windowStartOverride = windowStart;
    }

    protected override void ingest(QueueableContext context) {
        CapabilityProbe.ProbeResult cap = CapabilityProbe.runNow();
        if (cap == null || cap.hasEventLogFile != true) {
            ScanRunService.appendLog(scanRunId, 'EventLogFileIngest: skipped (EventLogFile not licensed)');
            return;
        }

        List<SObject> files = queryEventLogFiles();
        if (files == null || files.isEmpty()) {
            ScanRunService.appendLog(scanRunId, 'EventLogFileIngest: no EventLogFile rows for yesterday');
            return;
        }

        Integer totalEvents = 0;
        Integer totalFiles = 0;
        for (SObject elf : files) {
            List<Security_Event__c> events = parseFile(elf);
            if (events.isEmpty()) {
                continue;
            }
            Database.insert(events, false);
            totalEvents += events.size();
            totalFiles++;
        }

        ScanRunService.appendLog(
            scanRunId,
            'EventLogFileIngest: staged ' + totalEvents + ' events across ' + totalFiles + ' files'
        );
    }

    /**
     * Query EventLogFile via dynamic SOQL so non-Shield orgs (where the SObject
     * may be absent from the schema) still compile this class.
     */
    private List<SObject> queryEventLogFiles() {
        String typeList = '';
        Boolean first = true;
        for (String t : SUPPORTED_EVENT_TYPES) {
            if (!first) {
                typeList += ',';
            }
            typeList += '\'' + String.escapeSingleQuotes(t) + '\'';
            first = false;
        }
        String q =
            'SELECT Id, EventType, LogDate, LogFile, LogFileLength ' +
            'FROM EventLogFile ' +
            'WHERE LogDate = YESTERDAY AND EventType IN (' +
            typeList +
            ') ' +
            'LIMIT ' +
            FILE_LIMIT;
        try {
            return Database.query(q);
        } catch (Exception e) {
            ScanRunService.appendLog(scanRunId, 'EventLogFileIngest: query error ' + e.getMessage());
            return new List<SObject>();
        }
    }

    /**
     * Parse a single EventLogFile blob into Security_Event__c rows.
     * Caps at ROW_CAP_PER_FILE to stay inside DML and heap limits.
     */
    @TestVisible
    private static List<Security_Event__c> parseFile(SObject elf) {
        Blob logBlob;
        try {
            logBlob = (Blob) elf.get('LogFile');
        } catch (Exception e) {
            return new List<Security_Event__c>();
        }
        if (logBlob == null) {
            return new List<Security_Event__c>();
        }

        String csv = logBlob.toString();
        String elfType = (String) elf.get('EventType');
        return parseCsv(csv, elfType);
    }

    /**
     * Pure transformation from a decoded EventLogFile CSV string + its
     * EventType into Security_Event__c rows. Extracted from parseFile() so it
     * can be unit tested with a plain CSV String (EventLogFile is read-only and
     * cannot be inserted in tests). Behavior is identical to the prior inline
     * logic: same header lookup, type mapping, row cap, and Source_Json__c
     * truncation.
     */
    @TestVisible
    private static List<Security_Event__c> parseCsv(String csv, String elfType) {
        List<Security_Event__c> out = new List<Security_Event__c>();
        if (String.isBlank(csv)) {
            return out;
        }

        List<String> lines = csv.split('\n');
        if (lines.isEmpty()) {
            return out;
        }

        List<String> headers = splitCsvLine(lines[0]);
        if (headers.isEmpty()) {
            return out;
        }

        Integer timestampIdx = indexOfHeader(headers, 'TIMESTAMP_DERIVED');
        Integer userIdIdx = indexOfHeader(headers, 'USER_ID_DERIVED');

        String mappedType = SUPPORTED_EVENT_TYPES.contains(elfType) ? elfType : 'URI';

        Integer rowCount = 0;
        for (Integer i = 1; i < lines.size() && rowCount < ROW_CAP_PER_FILE; i++) {
            String line = lines[i];
            if (String.isBlank(line)) {
                continue;
            }
            List<String> cells = splitCsvLine(line);
            if (cells.isEmpty()) {
                continue;
            }

            Map<String, String> row = new Map<String, String>();
            for (Integer h = 0; h < headers.size() && h < cells.size(); h++) {
                row.put(headers[h], cells[h]);
            }

            Security_Event__c evt = new Security_Event__c();
            evt.Event_Type__c = mappedType;
            evt.Event_Time__c = parseTimestamp(timestampIdx, cells);
            evt.User__c = parseUserId(userIdIdx, cells);
            String json = JSON.serialize(row);
            evt.Source_Json__c = json.length() > SOURCE_JSON_MAX ? json.left(SOURCE_JSON_MAX) : json;
            // Composite_Key__c is a formula — do not assign.

            out.add(evt);
            rowCount++;
        }

        return out;
    }

    /**
     * Locate a header index by exact case-sensitive name; returns -1 if absent.
     */
    private static Integer indexOfHeader(List<String> headers, String name) {
        for (Integer i = 0; i < headers.size(); i++) {
            if (name.equals(headers[i] == null ? '' : headers[i].trim().replace('"', ''))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Best-effort timestamp parse from the TIMESTAMP_DERIVED column.
     * Falls back to Datetime.now() if the column is missing or unparseable.
     */
    private static Datetime parseTimestamp(Integer idx, List<String> cells) {
        if (idx < 0 || idx >= cells.size()) {
            return Datetime.now();
        }
        String raw = cells[idx];
        if (String.isBlank(raw)) {
            return Datetime.now();
        }
        String cleaned = raw.replace('"', '').trim();
        try {
            return (Datetime) JSON.deserialize('"' + cleaned + '"', Datetime.class);
        } catch (Exception e) {
            return Datetime.now();
        }
    }

    /**
     * Best-effort User Id parse from the USER_ID_DERIVED column.
     * Returns null if missing, blank, or not a valid 18-char Id.
     */
    private static Id parseUserId(Integer idx, List<String> cells) {
        if (idx < 0 || idx >= cells.size()) {
            return null;
        }
        String raw = cells[idx];
        if (String.isBlank(raw)) {
            return null;
        }
        String cleaned = raw.replace('"', '').trim();
        if (cleaned.length() != 15 && cleaned.length() != 18) {
            return null;
        }
        try {
            return Id.valueOf(cleaned);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Simple CSV line splitter that respects double-quoted fields containing
     * commas. EventLogFile output is well-formed CSV so this is sufficient.
     */
    private static List<String> splitCsvLine(String line) {
        List<String> out = new List<String>();
        if (line == null) {
            return out;
        }
        StringBuilder current = new StringBuilder();
        Boolean inQuotes = false;
        for (Integer i = 0; i < line.length(); i++) {
            String ch = line.substring(i, i + 1);
            if (ch == '"') {
                inQuotes = !inQuotes;
                continue;
            }
            if (ch == ',' && !inQuotes) {
                out.add(current.toString());
                current = new StringBuilder();
                continue;
            }
            current.append(ch);
        }
        out.add(current.toString());
        return out;
    }

    /** Apex has no StringBuilder; emulate with a List<String>+join. */
    private class StringBuilder {
        private List<String> parts = new List<String>();
        public StringBuilder append(String s) {
            parts.add(s);
            return this;
        }
        public override String toString() {
            return String.join(parts, '');
        }
    }
}
