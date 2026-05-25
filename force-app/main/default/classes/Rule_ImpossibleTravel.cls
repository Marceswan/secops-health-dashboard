/**
 * Detection rule: flags pairs of successful logins for the same user that
 * happen too close in time to be physically possible based on country
 * centroid distance.
 *
 * Reads Security_Event__c rows of type 'LoginHistory' inserted by the
 * LoginHistory ingest phase. For each user, sorts their logins by time
 * and inspects consecutive pairs: if the implied speed (km/h) exceeds
 * a threshold, a finding is raised.
 */
public with sharing class Rule_ImpossibleTravel implements DetectionRule {
    /** Threshold for "impossible" travel in km/h. ~1000 km/h ~ commercial jet. */
    private static final Double SPEED_THRESHOLD_KMH = 900.0;

    public String getDeveloperName() {
        return 'Impossible_Travel';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        Map<Id, List<Security_Event__c>> byUser = new Map<Id, List<Security_Event__c>>();
        for (Security_Event__c evt : [
            SELECT Id, User__c, Event_Time__c, Source_Json__c
            FROM Security_Event__c
            WHERE
                Event_Type__c = 'LoginHistory'
                AND User__c != NULL
                AND Event_Time__c >= :ctx.windowStart
                AND Event_Time__c <= :ctx.windowEnd
            ORDER BY User__c, Event_Time__c ASC
            LIMIT 50000
        ]) {
            if (!byUser.containsKey(evt.User__c)) {
                byUser.put(evt.User__c, new List<Security_Event__c>());
            }
            byUser.get(evt.User__c).add(evt);
        }

        for (Id userId : byUser.keySet()) {
            List<Security_Event__c> events = byUser.get(userId);
            for (Integer i = 1; i < events.size(); i++) {
                Security_Event__c prev = events[i - 1];
                Security_Event__c curr = events[i];
                String prevCountry = extractCountry(prev.Source_Json__c);
                String currCountry = extractCountry(curr.Source_Json__c);
                if (prevCountry == null || currCountry == null) {
                    continue;
                }
                Double distanceKm = LoginGeoLookup.roughDistance(prevCountry, currCountry);
                if (distanceKm == null || distanceKm == 0) {
                    continue;
                }
                Long elapsedMs = curr.Event_Time__c.getTime() - prev.Event_Time__c.getTime();
                if (elapsedMs <= 0) {
                    continue;
                }
                Double hours = elapsedMs / (1000.0 * 60.0 * 60.0);
                Double speedKmh = distanceKm / hours;
                if (speedKmh > SPEED_THRESHOLD_KMH) {
                    findings.add(
                        FindingFactory.build(
                            ctx.scanRunId,
                            getDeveloperName(),
                            'Login Anomaly',
                            SecOpsConstants.SEVERITY_CRITICAL,
                            userId,
                            null,
                            String.valueOf(curr.Id),
                            new Map<String, Object>{
                                'fromCountry' => prevCountry,
                                'toCountry' => currCountry,
                                'distanceKm' => distanceKm,
                                'elapsedHours' => hours,
                                'impliedSpeedKmh' => speedKmh,
                                'previousEventId' => prev.Id,
                                'previousEventTime' => prev.Event_Time__c,
                                'currentEventTime' => curr.Event_Time__c
                            }
                        )
                    );
                }
            }
        }
        return findings;
    }

    /**
     * Best-effort country-code extraction from the serialized LoginHistory
     * payload. Looks for 'CountryIso' (LoginHistory's standard column) and
     * falls back to 'Country' for tolerance.
     */
    private String extractCountry(String sourceJson) {
        if (String.isBlank(sourceJson)) {
            return null;
        }
        try {
            Map<String, Object> parsed = (Map<String, Object>) JSON.deserializeUntyped(sourceJson);
            Object cc = parsed.get('CountryIso');
            if (cc == null) {
                cc = parsed.get('Country');
            }
            return cc == null ? null : String.valueOf(cc).toUpperCase();
        } catch (Exception e) {
            return null;
        }
    }
}
