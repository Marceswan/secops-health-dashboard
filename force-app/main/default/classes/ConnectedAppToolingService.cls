/**
 * Thin wrapper around the Tooling API for ConnectedApplication / OAuth token
 * discovery. Uses the SecOpsToolingApi named credential so callers do not need
 * to manage session ids or endpoints.
 *
 * Callouts are isolated here so OAuthInventoryIngest can be unit tested with a
 * Test.setMock against this class.
 */
public with sharing class ConnectedAppToolingService {
    private static final String NC_PATH = 'callout:SecOpsToolingApi/services/data/v64.0/tooling/query/?q=';

    /**
     * Fetches ConnectedApplication rows via the Tooling API and returns a map
     * keyed by the ConnectedApplication Id. Values are the raw row Map so the
     * caller can pluck whatever fields they need without re-issuing the call.
     *
     * Returns an empty map (not null) on any non-200 response or parse error so
     * the ingest pipeline keeps moving instead of failing the whole scan.
     */
    public static Map<String, Map<String, Object>> fetchConnectedApps() {
        Map<String, Map<String, Object>> result = new Map<String, Map<String, Object>>();

        String soql = 'SELECT Id, Name, OptionsAllowAdminApprovedUsersOnly, MobileSessionTimeout, CreatedDate FROM ConnectedApplication';
        String url = NC_PATH + EncodingUtil.urlEncode(soql, 'UTF-8');

        HttpRequest req = new HttpRequest();
        req.setEndpoint(url);
        req.setMethod('GET');
        req.setHeader('Accept', 'application/json');
        req.setTimeout(20000);

        HttpResponse res;
        try {
            res = new Http().send(req);
        } catch (Exception e) {
            return result;
        }

        if (res == null || res.getStatusCode() != 200) {
            return result;
        }

        try {
            Map<String, Object> body = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
            List<Object> records = (List<Object>) body.get('records');
            if (records == null) {
                return result;
            }
            for (Object o : records) {
                Map<String, Object> row = (Map<String, Object>) o;
                String id = (String) row.get('Id');
                if (id != null) {
                    result.put(id, row);
                }
            }
        } catch (Exception e) {
            // swallow - return what we have
        }
        return result;
    }
}
