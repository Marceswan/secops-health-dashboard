/**
 * Destructive remediation actions for SecOps findings.
 *
 * Each public method:
 *  - Validates the relevant custom permission via FeatureManagement.
 *  - Performs the destructive action (revoke OAuth token, kill session,
 *    block connected app, freeze user, force password reset).
 *  - Logs an Action_Audit__c row (Success or Failure).
 *  - Appends a stamped entry to the finding's Action_History__c.
 *  - Flips Security_Finding__c.Status__c to Remediated on success.
 *
 * Throws RemediationException on permission or runtime failure so callers
 * (AuraEnabled wrappers, future Flow plug-ins) can surface a clean message.
 */
public with sharing class RemediationService {
    /** Raised for permission denial or downstream remediation failure. */
    public class RemediationException extends Exception {
    }

    private static final String NC_PATCH_PATH = 'callout:SecOpsToolingApi/services/data/v64.0/tooling/sobjects/ConnectedApplication/';

    /**
     * Revoke an OAuth token row by Id. If tokenId is null or the row does not
     * exist, the call still succeeds (idempotent) and logs an audit entry.
     */
    public static void revokeOauthToken(Id findingId, Id tokenId) {
        requirePermission('SecOps_Remediate_App');
        Datetime actionAt = Datetime.now();
        try {
            Integer deleted = 0;
            if (tokenId != null) {
                List<SObject> rows = Database.query('SELECT Id FROM OauthToken WHERE Id = :tokenId LIMIT 1');
                if (!rows.isEmpty()) {
                    delete rows;
                    deleted = rows.size();
                }
            }
            Map<String, Object> params = new Map<String, Object>{ 'tokenId' => tokenId, 'deleted' => deleted };
            logAudit(findingId, 'RevokeToken', tokenId, params, 'Success', null, actionAt);
            applyRemediatedStatus(findingId);
        } catch (Exception e) {
            logAudit(
                findingId,
                'RevokeToken',
                tokenId,
                new Map<String, Object>{ 'tokenId' => tokenId },
                'Failure',
                e.getMessage(),
                actionAt
            );
            throw new RemediationException('Revoke OAuth token failed: ' + e.getMessage());
        }
    }

    /**
     * Invalidate one specific AuthSession (sessionId) or every non-current
     * session for the given user when sessionId is null.
     */
    public static void killSession(Id findingId, Id userId, Id sessionId) {
        requirePermission('SecOps_Remediate_User');
        Datetime actionAt = Datetime.now();
        try {
            // Auth.SessionManagement does not expose a session-id invalidation
            // method in API 62, so we invalidate by deleting AuthSession rows.
            List<AuthSession> targets = new List<AuthSession>();
            if (sessionId != null) {
                targets.add(new AuthSession(Id = sessionId));
            } else if (userId != null) {
                targets = [SELECT Id FROM AuthSession WHERE UsersId = :userId AND IsCurrent = FALSE];
            }
            if (!targets.isEmpty()) {
                delete targets;
            }
            Map<String, Object> params = new Map<String, Object>{
                'userId' => userId,
                'sessionId' => sessionId,
                'invalidated' => targets.size()
            };
            logAudit(
                findingId,
                'KillSession',
                sessionId != null ? sessionId : userId,
                params,
                'Success',
                null,
                actionAt
            );
            applyRemediatedStatus(findingId);
        } catch (Exception e) {
            logAudit(
                findingId,
                'KillSession',
                sessionId != null ? sessionId : userId,
                new Map<String, Object>{ 'userId' => userId, 'sessionId' => sessionId },
                'Failure',
                e.getMessage(),
                actionAt
            );
            throw new RemediationException('Kill session failed: ' + e.getMessage());
        }
    }

    /**
     * Deactivate a ConnectedApplication via Tooling API PATCH. Uses the
     * SecOpsToolingApi named credential. Expects 204 No Content on success.
     */
    public static void blockConnectedApp(Id findingId, String connectedAppId) {
        requirePermission('SecOps_Remediate_App');
        Datetime actionAt = Datetime.now();
        Integer statusCode = 0;
        try {
            if (String.isBlank(connectedAppId)) {
                throw new RemediationException('connectedAppId is required');
            }
            HttpRequest req = new HttpRequest();
            req.setEndpoint(NC_PATCH_PATH + connectedAppId);
            req.setMethod('PATCH');
            req.setHeader('Content-Type', 'application/json');
            req.setBody('{"IsActive":false}');
            req.setTimeout(20000);
            HttpResponse res = new Http().send(req);
            statusCode = res == null ? 0 : res.getStatusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new RemediationException('Tooling API returned ' + statusCode);
            }
            Map<String, Object> params = new Map<String, Object>{
                'connectedAppId' => connectedAppId,
                'statusCode' => statusCode
            };
            logAudit(findingId, 'BlockApp', connectedAppId, params, 'Success', null, actionAt);
            applyRemediatedStatus(findingId);
        } catch (Exception e) {
            logAudit(
                findingId,
                'BlockApp',
                connectedAppId,
                new Map<String, Object>{ 'connectedAppId' => connectedAppId, 'statusCode' => statusCode },
                'Failure',
                e.getMessage(),
                actionAt
            );
            throw new RemediationException('Block connected app failed: ' + e.getMessage());
        }
    }

    /**
     * Freeze a user by setting UserLogin.IsFrozen = true.
     */
    public static void freezeUser(Id findingId, Id userId) {
        requirePermission('SecOps_Remediate_User');
        Datetime actionAt = Datetime.now();
        try {
            if (userId == null) {
                throw new RemediationException('userId is required');
            }
            List<UserLogin> logins = [SELECT Id, IsFrozen FROM UserLogin WHERE UserId = :userId LIMIT 1];
            if (logins.isEmpty()) {
                throw new RemediationException('No UserLogin row for user ' + userId);
            }
            UserLogin ul = logins[0];
            ul.IsFrozen = true;
            update ul;
            Map<String, Object> params = new Map<String, Object>{ 'userId' => userId };
            logAudit(findingId, 'FreezeUser', userId, params, 'Success', null, actionAt);
            applyRemediatedStatus(findingId);
        } catch (Exception e) {
            logAudit(
                findingId,
                'FreezeUser',
                userId,
                new Map<String, Object>{ 'userId' => userId },
                'Failure',
                e.getMessage(),
                actionAt
            );
            throw new RemediationException('Freeze user failed: ' + e.getMessage());
        }
    }

    /**
     * Trigger a password reset (and email reset link) for the target user.
     */
    public static void forcePasswordReset(Id findingId, Id userId) {
        requirePermission('SecOps_Remediate_User');
        Datetime actionAt = Datetime.now();
        try {
            if (userId == null) {
                throw new RemediationException('userId is required');
            }
            System.resetPassword(userId, true);
            Map<String, Object> params = new Map<String, Object>{ 'userId' => userId };
            logAudit(findingId, 'ForceReset', userId, params, 'Success', null, actionAt);
            applyRemediatedStatus(findingId);
        } catch (Exception e) {
            logAudit(
                findingId,
                'ForceReset',
                userId,
                new Map<String, Object>{ 'userId' => userId },
                'Failure',
                e.getMessage(),
                actionAt
            );
            throw new RemediationException('Force password reset failed: ' + e.getMessage());
        }
    }

    /**
     * Validate that the running user has been granted the named custom
     * permission. FeatureManagement avoids requiring a SOQL query per call.
     */
    private static void requirePermission(String permName) {
        if (!FeatureManagement.checkPermission(permName)) {
            throw new RemediationException('Missing custom permission: ' + permName);
        }
    }

    /**
     * Insert an Action_Audit__c row and append a stamped entry to the
     * parent finding's Action_History__c. Best-effort: history append
     * failure does not roll back the audit write.
     */
    private static void logAudit(
        Id findingId,
        String actionType,
        Object targetId,
        Map<String, Object> params,
        String result,
        String errorMsg,
        Datetime actionAt
    ) {
        if (findingId == null) {
            return;
        }
        Action_Audit__c a = new Action_Audit__c();
        a.Finding__c = findingId;
        a.Action_Type__c = actionType;
        a.Actor__c = UserInfo.getUserId();
        a.Action_Time__c = actionAt;
        if (targetId != null) {
            String s = String.valueOf(targetId);
            a.Target_Id__c = s.length() > 18 ? s.substring(0, 18) : s;
        }
        a.Parameters_Json__c = JSON.serialize(params == null ? new Map<String, Object>() : params);
        a.Result__c = result;
        if (String.isNotBlank(errorMsg)) {
            a.Error__c = errorMsg;
        }
        insert a;

        try {
            List<Security_Finding__c> rows = [
                SELECT Id, Action_History__c
                FROM Security_Finding__c
                WHERE Id = :findingId
                LIMIT 1
            ];
            if (!rows.isEmpty()) {
                Security_Finding__c f = rows[0];
                String stamp =
                    actionAt.format('yyyy-MM-dd HH:mm:ss') +
                    ' ' +
                    UserInfo.getUserId() +
                    ' ' +
                    actionType +
                    ' [' +
                    result +
                    ']';
                if (String.isNotBlank(errorMsg)) {
                    stamp += ': ' + errorMsg;
                }
                f.Action_History__c = (String.isBlank(f.Action_History__c) ? '' : f.Action_History__c + '\n') + stamp;
                update f;
            }
        } catch (Exception ignored) {
            // best-effort history append
        }
    }

    /**
     * Mark the source finding Remediated. Resolution metadata mirrors
     * WorkflowController.markRemediated so the UI reads consistently.
     */
    private static void applyRemediatedStatus(Id findingId) {
        if (findingId == null) {
            return;
        }
        try {
            List<Security_Finding__c> rows = [
                SELECT Id, Status__c, Resolved_At__c, Resolved_By__c
                FROM Security_Finding__c
                WHERE Id = :findingId
                LIMIT 1
            ];
            if (rows.isEmpty()) {
                return;
            }
            Security_Finding__c f = rows[0];
            f.Status__c = SecOpsConstants.STATUS_REMEDIATED;
            f.Resolved_At__c = Datetime.now();
            f.Resolved_By__c = UserInfo.getUserId();
            update f;
        } catch (Exception ignored) {
            // status flip is best-effort
        }
    }
}
