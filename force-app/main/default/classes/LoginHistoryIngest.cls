/**
 * Ingest phase that surveys LoginHistory in the trailing window.
 *
 * Note: LoginHistory is read-only at the platform level. Rather than stage rows
 * into Security_Event__c (which only makes sense for Shield EventLogFile data),
 * detection rules query LoginHistory directly within their own evaluate() calls.
 * This ingest exists to confirm access, log progress, and provide a clean
 * extension point if we later want to materialize rows.
 *
 * Runs in chunks to stay within governor limits. Chunk-to-chunk continuation
 * is owned by this class; phase transitions (LoginHistory -> OAuthInventory
 * -> SetupAudit -> PermissionChange -> DETECTION -> COMPLETE) are owned by
 * ScanOrchestrator.
 */
public with sharing class LoginHistoryIngest extends IngestBase {
    private static final Integer DEFAULT_CHUNK_SIZE = 200;
    private static final Integer LOOKBACK_DAYS = 180;

    private Integer chunkIndex;
    private Integer chunkSize;
    private Datetime lastLoginTimeSeen;
    private Datetime windowStartOverride;

    public LoginHistoryIngest(Id scanRunId) {
        super(scanRunId);
        this.chunkIndex = 0;
        this.chunkSize = DEFAULT_CHUNK_SIZE;
        this.lastLoginTimeSeen = null;
        this.windowStartOverride = null;
    }

    public LoginHistoryIngest(Id scanRunId, Datetime windowStart) {
        super(scanRunId);
        this.chunkIndex = 0;
        this.chunkSize = DEFAULT_CHUNK_SIZE;
        this.lastLoginTimeSeen = null;
        this.windowStartOverride = windowStart;
    }

    public LoginHistoryIngest(Id scanRunId, Integer chunkIndex, Integer chunkSize, Datetime lastLoginTimeSeen) {
        super(scanRunId);
        this.chunkIndex = chunkIndex;
        this.chunkSize = chunkSize;
        this.lastLoginTimeSeen = lastLoginTimeSeen;
        this.windowStartOverride = null;
    }

    public LoginHistoryIngest(
        Id scanRunId,
        Integer chunkIndex,
        Integer chunkSize,
        Datetime lastLoginTimeSeen,
        Datetime windowStart
    ) {
        super(scanRunId);
        this.chunkIndex = chunkIndex;
        this.chunkSize = chunkSize;
        this.lastLoginTimeSeen = lastLoginTimeSeen;
        this.windowStartOverride = windowStart;
    }

    protected override void ingest(QueueableContext context) {
        Datetime windowStart = windowStartOverride != null
            ? windowStartOverride
            : Datetime.now().addDays(-LOOKBACK_DAYS);
        Datetime cursor = lastLoginTimeSeen != null ? lastLoginTimeSeen : windowStart;

        List<LoginHistory> rows = [
            SELECT
                Id,
                UserId,
                LoginTime,
                SourceIp,
                LoginType,
                Status,
                Application,
                ClientVersion,
                ApiType,
                ApiVersion,
                Browser,
                Platform,
                CountryIso
            FROM LoginHistory
            WHERE LoginTime > :cursor AND LoginTime >= :windowStart
            ORDER BY LoginTime ASC
            LIMIT :chunkSize
        ];

        if (rows.isEmpty()) {
            ScanRunService.appendLog(scanRunId, 'LoginHistoryIngest: complete after chunk ' + chunkIndex);
            return;
        }

        Datetime newWatermark = watermarkOf(rows);
        ScanRunService.appendLog(scanRunId, buildSurveyLog(chunkIndex, rows));

        if (!Test.isRunningTest() && rows.size() == chunkSize) {
            System.enqueueJob(
                new LoginHistoryIngest(scanRunId, chunkIndex + 1, chunkSize, newWatermark, windowStartOverride)
            );
        }
    }

    /**
     * Compute the chunk watermark (LoginTime of the last surveyed row) used as
     * the cursor for the next chunk. Extracted from ingest() so it can be unit
     * tested with in-memory LoginHistory rows (a read-only platform object that
     * cannot be inserted in tests). Behavior is identical to the inline logic.
     */
    @TestVisible
    private static Datetime watermarkOf(List<LoginHistory> rows) {
        return rows[rows.size() - 1].LoginTime;
    }

    /**
     * Build the per-chunk survey log line. Extracted alongside watermarkOf so
     * the row-derived outputs of ingest() are unit testable without inserting
     * read-only LoginHistory rows. Behavior is identical to the inline logic.
     */
    @TestVisible
    private static String buildSurveyLog(Integer chunkIndex, List<LoginHistory> rows) {
        return 'LoginHistoryIngest: chunk ' + chunkIndex + ' surveyed ' + rows.size() + ' rows';
    }
}
