@IsTest
private class EventLogFileIngest_Test {
    /**
     * On a scratch org / dev sandbox without Shield, CapabilityProbe reports
     * hasEventLogFile=false. The ingest must log a "skipped" line and exit
     * cleanly without failing the parent Scan_Run.
     */
    @IsTest
    static void skipsWhenEventLogFileNotLicensed() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new EventLogFileIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertNotEquals(
            'Failed',
            run.Status__c,
            'EventLogFileIngest must not fail the Scan_Run on non-Shield orgs'
        );
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('EventLogFileIngest'),
            'Log should reference EventLogFileIngest'
        );
    }

    /**
     * Verify the explicit-window constructor wires through without error.
     */
    @IsTest
    static void windowedConstructor_runsCleanly() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new EventLogFileIngest(runId, Datetime.now().addDays(-1)));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'Windowed constructor must not fail the Scan_Run');
    }

    // ---------------------------------------------------------------------
    // parseCsv() transformation coverage. EventLogFile is read-only and not
    // insertable in tests, so we exercise the extracted pure transformation
    // with synthetic decoded CSV strings instead of real LogFile blobs.
    // ---------------------------------------------------------------------

    /**
     * A well-formed CSV with both derived columns maps each data row into a
     * Security_Event__c carrying the EventType, parsed timestamp, and parsed
     * User Id. Source_Json__c captures the full row as a header->cell map.
     */
    @IsTest
    static void parseFile_nullLogFile_returnsEmpty() {
        EventLogFile elf = (EventLogFile) JSON.deserialize(
            '{"attributes":{"type":"EventLogFile"},"EventType":"Login"}',
            EventLogFile.class
        );
        List<Security_Event__c> events = EventLogFileIngest.parseFile(elf);
        System.assertEquals(0, events.size(), 'A null LogFile yields no events');
    }

    @IsTest
    static void parseCsv_mapsRowsWithDerivedColumns() {
        String userId = UserInfo.getUserId(); // a real 18-char Id
        String csv =
            'EVENT_TYPE,TIMESTAMP_DERIVED,USER_ID_DERIVED,REQUEST_ID\n' +
            'API,2026-01-15T00:00:00.000Z,' + userId + ',ABC123\n' +
            'API,2026-01-16T12:30:00.000Z,' + userId + ',DEF456';

        Test.startTest();
        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'ApiTotalUsage');
        Test.stopTest();

        System.assertEquals(2, events.size(), 'Two data rows should produce two events');

        Security_Event__c first = events[0];
        System.assertEquals('ApiTotalUsage', first.Event_Type__c, 'Supported EventType maps through unchanged');
        System.assertEquals(
            Datetime.newInstanceGmt(2026, 1, 15, 0, 0, 0),
            first.Event_Time__c,
            'TIMESTAMP_DERIVED should parse into Event_Time__c'
        );
        System.assertEquals(userId, String.valueOf(first.User__c), 'USER_ID_DERIVED should parse into User__c');
        System.assert(first.Source_Json__c.contains('ABC123'), 'Source_Json__c should contain the raw row data');
    }

    /**
     * An EventType not in SUPPORTED_EVENT_TYPES is coerced to the catch-all
     * 'URI' picklist value rather than written through verbatim.
     */
    @IsTest
    static void parseCsv_unsupportedTypeMapsToUri() {
        String csv =
            'TIMESTAMP_DERIVED,USER_ID_DERIVED\n' +
            '2026-02-01T08:00:00.000Z,';

        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'SomethingUnmapped');

        System.assertEquals(1, events.size(), 'One data row should produce one event');
        System.assertEquals('URI', events[0].Event_Type__c, 'Unsupported EventType should map to URI');
    }

    /**
     * When the derived columns are absent, timestamp falls back to now() and
     * the User__c stays null. Quoted fields containing commas are honored.
     */
    @IsTest
    static void parseCsv_missingDerivedColumnsAndQuotedCommas() {
        String csv =
            'REQUEST_ID,NOTE\n' +
            '"R,1","hello, world"';

        Datetime before = Datetime.now().addSeconds(-5);
        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'URI');
        Datetime after = Datetime.now().addSeconds(5);

        System.assertEquals(1, events.size(), 'One data row expected');
        Security_Event__c evt = events[0];
        System.assertEquals('URI', evt.Event_Type__c);
        System.assertEquals(null, evt.User__c, 'Missing USER_ID_DERIVED leaves User__c null');
        System.assert(
            evt.Event_Time__c >= before && evt.Event_Time__c <= after,
            'Missing timestamp column should fall back to now()'
        );
        // Quoted comma-bearing cells should not be split into extra columns.
        System.assert(evt.Source_Json__c.contains('R,1'), 'Quoted comma field R,1 should survive intact');
        System.assert(evt.Source_Json__c.contains('hello, world'), 'Quoted comma field should survive intact');
    }

    /**
     * Unparseable / short Id and bad timestamp values fall back gracefully:
     * User__c null, Event_Time__c defaults to now().
     */
    @IsTest
    static void parseCsv_badTimestampAndShortIdFallBack() {
        String csv =
            'TIMESTAMP_DERIVED,USER_ID_DERIVED\n' +
            'not-a-date,00Dxx';

        Datetime before = Datetime.now().addSeconds(-5);
        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'Login');
        Datetime after = Datetime.now().addSeconds(5);

        System.assertEquals(1, events.size());
        System.assertEquals('Login', events[0].Event_Type__c);
        System.assertEquals(null, events[0].User__c, 'Non-15/18-char value should not parse into an Id');
        System.assert(
            events[0].Event_Time__c >= before && events[0].Event_Time__c <= after,
            'Unparseable timestamp should fall back to now()'
        );
    }

    /**
     * Blank input, header-only input, and blank interior data lines produce no
     * events (and blank lines are skipped, not errored).
     */
    @IsTest
    static void parseCsv_emptyAndBlankInputs() {
        System.assertEquals(0, EventLogFileIngest.parseCsv(null, 'Login').size(), 'Null CSV yields no events');
        System.assertEquals(0, EventLogFileIngest.parseCsv('', 'Login').size(), 'Blank CSV yields no events');

        // Header row only -> no data rows.
        System.assertEquals(
            0,
            EventLogFileIngest.parseCsv('TIMESTAMP_DERIVED,USER_ID_DERIVED', 'Login').size(),
            'Header-only CSV yields no events'
        );

        // Interior blank line is skipped; one real data row remains.
        String csv = 'A,B\n\nx,y';
        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'Login');
        System.assertEquals(1, events.size(), 'Blank interior line should be skipped, one event remains');
    }

    /**
     * Parsing respects the per-file row cap (5000). Confirm an oversized file
     * is truncated at the cap.
     */
    @IsTest
    static void parseCsv_respectsRowCap() {
        String[] lines = new List<String>{ 'A' };
        for (Integer i = 0; i < 5050; i++) {
            lines.add('v' + i);
        }
        String csv = String.join(lines, '\n');

        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'URI');
        System.assertEquals(5000, events.size(), 'Row count should be capped at ROW_CAP_PER_FILE (5000)');
    }

    /**
     * An inserted Security_Event__c built by the parser persists with the
     * required fields populated, proving the produced rows are DML-valid
     * against the restricted Event_Type__c picklist.
     */
    @IsTest
    static void parseCsv_producesInsertableRows() {
        String csv =
            'TIMESTAMP_DERIVED,USER_ID_DERIVED\n' +
            '2026-03-01T00:00:00.000Z,' + UserInfo.getUserId();

        List<Security_Event__c> events = EventLogFileIngest.parseCsv(csv, 'Login');
        System.assertEquals(1, events.size());

        insert events;

        Security_Event__c reloaded = [
            SELECT Event_Type__c, Event_Time__c, User__c, Source_Json__c
            FROM Security_Event__c
            WHERE Id = :events[0].Id
        ];
        System.assertEquals('Login', reloaded.Event_Type__c, 'Restricted picklist value Login must persist');
        System.assertNotEquals(null, reloaded.Event_Time__c, 'Event_Time__c is required and must persist');
    }
}
