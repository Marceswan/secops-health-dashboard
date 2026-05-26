/**
 * Baseline engine: builds and queries User_Baseline__c rows.
 *
 * A baseline summarizes a user's "normal" login behavior over the prior
 * BASELINE_LOOKBACK_DAYS window: which countries they logged in from,
 * which /24 IP ranges they used, which connected apps they authorized,
 * which browsers they ran, and what their hour-of-day login histogram
 * looks like. Detection rules use these baselines to flag deviations.
 *
 * Construction is a single SOQL aggregation over LoginHistory plus a
 * lookup over OauthToken for the app set. Helpers are stateless so
 * rules can ask "is this country in baseline?" cheaply.
 */
public with sharing class BaselineEngine {
    /** Build (but do not insert) a User_Baseline__c for a given user. */
    public static User_Baseline__c buildForUser(Id userId, Datetime sinceWhen) {
        List<LoginHistory> logins = [
            SELECT Id, UserId, SourceIp, CountryIso, Browser, LoginTime, Status
            FROM LoginHistory
            WHERE UserId = :userId AND LoginTime >= :sinceWhen
            LIMIT 40000
        ];

        Set<String> appNames = new Set<String>();
        for (OauthToken tok : [
            SELECT Id, AppName
            FROM OauthToken
            WHERE UserId = :userId
            LIMIT 5000
        ]) {
            if (tok.AppName != null) {
                appNames.add(tok.AppName);
            }
        }

        return buildFromRecords(userId, logins, appNames);
    }

    /**
     * Bulk variant of buildForUser: builds baselines for many users with a
     * fixed two SOQL queries (LoginHistory + OauthToken) regardless of how many
     * users are passed in. Callers that iterate over a user set MUST use this
     * instead of calling buildForUser per user, which would breach the SOQL
     * governor limit.
     *
     * @return Map keyed by User Id; every input id is present in the result.
     */
    public static Map<Id, User_Baseline__c> buildForUsers(Set<Id> userIds, Datetime sinceWhen) {
        Map<Id, User_Baseline__c> out = new Map<Id, User_Baseline__c>();
        if (userIds == null || userIds.isEmpty()) {
            return out;
        }

        // Row limits are kept comfortably below the 50k per-transaction cap so
        // that the LoginHistory + OauthToken reads combined cannot breach it,
        // even when the caller hands us a chunk of heavy-login users.
        Map<Id, List<LoginHistory>> loginsByUser = new Map<Id, List<LoginHistory>>();
        for (LoginHistory lh : [
            SELECT Id, UserId, SourceIp, CountryIso, Browser, LoginTime, Status
            FROM LoginHistory
            WHERE UserId IN :userIds AND LoginTime >= :sinceWhen
            LIMIT 40000
        ]) {
            List<LoginHistory> bucket = loginsByUser.get(lh.UserId);
            if (bucket == null) {
                bucket = new List<LoginHistory>();
                loginsByUser.put(lh.UserId, bucket);
            }
            bucket.add(lh);
        }

        Map<Id, Set<String>> appsByUser = new Map<Id, Set<String>>();
        for (OauthToken tok : [
            SELECT Id, AppName, UserId
            FROM OauthToken
            WHERE UserId IN :userIds
            LIMIT 8000
        ]) {
            Set<String> apps = appsByUser.get(tok.UserId);
            if (apps == null) {
                apps = new Set<String>();
                appsByUser.put(tok.UserId, apps);
            }
            if (tok.AppName != null) {
                apps.add(tok.AppName);
            }
        }

        for (Id uid : userIds) {
            out.put(uid, buildFromRecords(uid, loginsByUser.get(uid), appsByUser.get(uid)));
        }
        return out;
    }

    /**
     * Aggregate pre-fetched LoginHistory and OAuth app names into a baseline.
     * Stateless and SOQL-free so both the single and bulk builders can share it.
     */
    private static User_Baseline__c buildFromRecords(Id userId, List<LoginHistory> logins, Set<String> appNames) {
        Set<String> countries = new Set<String>();
        Set<String> ip24s = new Set<String>();
        Set<String> browsers = new Set<String>();
        Integer[] hourCounts = new Integer[24];
        for (Integer i = 0; i < 24; i++) {
            hourCounts[i] = 0;
        }
        Integer sample = 0;

        if (logins != null) {
            for (LoginHistory lh : logins) {
                if (lh.Status != 'Success') {
                    continue;
                }
                sample++;
                if (lh.CountryIso != null) {
                    countries.add(lh.CountryIso);
                }
                if (lh.Browser != null) {
                    browsers.add(lh.Browser);
                }
                String ip24 = toIp24(lh.SourceIp);
                if (ip24 != null) {
                    ip24s.add(ip24);
                }
                if (lh.LoginTime != null) {
                    Integer h = lh.LoginTime.hour();
                    if (h >= 0 && h < 24) {
                        hourCounts[h] = hourCounts[h] + 1;
                    }
                }
            }
        }

        User_Baseline__c b = new User_Baseline__c();
        b.User__c = userId;
        b.User_Id_External__c = userId;
        b.Country_Set__c = joinSet(countries);
        b.Ip24_Set__c = joinSet(ip24s);
        b.Browser_Set__c = joinSet(browsers);
        b.App_Set__c = joinSet(appNames == null ? new Set<String>() : appNames);
        b.Hour_Histogram__c = JSON.serialize(hourCounts);
        b.Sample_Size__c = sample;
        b.Last_Refreshed__c = Datetime.now();
        return b;
    }

    /** Single-user baseline lookup. Returns null if no row exists. */
    public static User_Baseline__c getBaselineFor(Id userId) {
        if (userId == null) {
            return null;
        }
        List<User_Baseline__c> rows = [
            SELECT
                Id,
                User__c,
                User_Id_External__c,
                Country_Set__c,
                Ip24_Set__c,
                Browser_Set__c,
                App_Set__c,
                Hour_Histogram__c,
                Sample_Size__c,
                Last_Refreshed__c
            FROM User_Baseline__c
            WHERE User__c = :userId
            LIMIT 1
        ];
        return rows.isEmpty() ? null : rows[0];
    }

    /** Bulk loader keyed by User__c for callers iterating many records. */
    public static Map<Id, User_Baseline__c> loadBaselines(Set<Id> userIds) {
        Map<Id, User_Baseline__c> byUser = new Map<Id, User_Baseline__c>();
        if (userIds == null || userIds.isEmpty()) {
            return byUser;
        }
        for (User_Baseline__c b : [
            SELECT
                Id,
                User__c,
                User_Id_External__c,
                Country_Set__c,
                Ip24_Set__c,
                Browser_Set__c,
                App_Set__c,
                Hour_Histogram__c,
                Sample_Size__c,
                Last_Refreshed__c
            FROM User_Baseline__c
            WHERE User__c IN :userIds
        ]) {
            byUser.put(b.User__c, b);
        }
        return byUser;
    }

    /** True when the baseline has enough samples to be trusted by rules. */
    public static Boolean isWarmedUp(User_Baseline__c b) {
        if (b == null || b.Sample_Size__c == null) {
            return false;
        }
        return b.Sample_Size__c >= SecOpsConstants.BASELINE_WARMUP_THRESHOLD;
    }

    /** Membership check against the country set; null/empty baselines return false. */
    public static Boolean isCountryInBaseline(User_Baseline__c b, String country) {
        if (b == null || String.isBlank(b.Country_Set__c) || String.isBlank(country)) {
            return false;
        }
        return splitSet(b.Country_Set__c).contains(country);
    }

    /** Membership check against the IP-24 set; null/empty baselines return false. */
    public static Boolean isIp24InBaseline(User_Baseline__c b, String ip24) {
        if (b == null || String.isBlank(b.Ip24_Set__c) || String.isBlank(ip24)) {
            return false;
        }
        return splitSet(b.Ip24_Set__c).contains(ip24);
    }

    /** Membership check against the app set; null/empty baselines return false. */
    public static Boolean isAppInBaseline(User_Baseline__c b, String appName) {
        if (b == null || String.isBlank(b.App_Set__c) || String.isBlank(appName)) {
            return false;
        }
        return splitSet(b.App_Set__c).contains(appName);
    }

    /**
     * True when the given hour of day is "anomalous" for the baseline.
     * Anomalous = the hour represents less than 2% of historical successful
     * logins AND the baseline is warmed up. Returns false for cold baselines.
     */
    public static Boolean isHourAnomalous(User_Baseline__c b, Integer hourOfDay) {
        if (!isWarmedUp(b) || hourOfDay == null || hourOfDay < 0 || hourOfDay >= 24) {
            return false;
        }
        if (String.isBlank(b.Hour_Histogram__c)) {
            return false;
        }
        List<Object> raw;
        try {
            raw = (List<Object>) JSON.deserializeUntyped(b.Hour_Histogram__c);
        } catch (Exception e) {
            return false;
        }
        if (raw == null || raw.size() < 24) {
            return false;
        }
        Integer total = 0;
        for (Object o : raw) {
            total += ((Integer) o);
        }
        if (total <= 0) {
            return false;
        }
        Integer count = (Integer) raw[hourOfDay];
        Decimal pct = (Decimal.valueOf(count) / Decimal.valueOf(total));
        return pct < 0.02;
    }

    /**
     * Aggregate health stats for the baseline coverage card on the Configure tab.
     *
     * totalUsers          — count of active, non-system users in the org
     * usersWithBaseline   — count of distinct users that have at least one User_Baseline__c
     * usersWithoutBaseline — totalUsers - usersWithBaseline
     * oldestRefresh       — earliest Last_Refreshed__c across all baselines (or null)
     * newestRefresh       — latest Last_Refreshed__c across all baselines (or null)
     */
    @AuraEnabled(cacheable=true)
    public static Map<String, Object> getHealthStats() {
        Map<String, Object> stats = new Map<String, Object>();

        Integer totalUsers = [
            SELECT COUNT()
            FROM User
            WHERE IsActive = TRUE AND UserType = 'Standard'
        ];

        Integer usersWithBaseline = [SELECT COUNT() FROM User_Baseline__c];

        Datetime oldestRefresh = null;
        Datetime newestRefresh = null;
        for (AggregateResult ar : [
            SELECT MIN(Last_Refreshed__c) minRef, MAX(Last_Refreshed__c) maxRef
            FROM User_Baseline__c
        ]) {
            oldestRefresh = (Datetime) ar.get('minRef');
            newestRefresh = (Datetime) ar.get('maxRef');
        }

        stats.put('totalUsers', totalUsers);
        stats.put('usersWithBaseline', usersWithBaseline);
        stats.put('usersWithoutBaseline', Math.max(0, totalUsers - usersWithBaseline));
        stats.put('oldestRefresh', oldestRefresh);
        stats.put('newestRefresh', newestRefresh);
        return stats;
    }

    /**
     * Enqueue an on-demand refresh of every user's baseline.
     * Fire-and-forget: caller does not get a handle back. The queue progress
     * shows up in the standard Apex Jobs setup page.
     */
    @AuraEnabled
    public static void refreshAllNow() {
        System.enqueueJob(new UserBaselineRefresh());
    }

    /** Convert "10.20.30.45" to "10.20.30.0/24". Returns null if not parseable IPv4. */
    public static String toIp24(String ip) {
        if (String.isBlank(ip)) {
            return null;
        }
        List<String> parts = ip.split('\\.');
        if (parts.size() != 4) {
            return null;
        }
        for (Integer i = 0; i < 3; i++) {
            if (!parts[i].isNumeric()) {
                return null;
            }
        }
        return parts[0] + '.' + parts[1] + '.' + parts[2] + '.0/24';
    }

    private static String joinSet(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return '';
        }
        List<String> sorted = new List<String>(values);
        sorted.sort();
        return String.join(sorted, '\n');
    }

    private static Set<String> splitSet(String raw) {
        Set<String> out = new Set<String>();
        if (String.isBlank(raw)) {
            return out;
        }
        for (String line : raw.split('\n')) {
            String trimmed = line.trim();
            if (!String.isBlank(trimmed)) {
                out.add(trimmed);
            }
        }
        return out;
    }
}
