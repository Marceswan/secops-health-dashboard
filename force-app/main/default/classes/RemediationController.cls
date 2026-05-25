/**
 * AuraEnabled wrappers around RemediationService for the secopsRemediationPanel
 * LWC. Each wrapper surfaces RemediationException as AuraHandledException so
 * LWC error handlers see a clean message.
 */
public with sharing class RemediationController {
    /**
     * Map of custom permission name -> whether the running user has it.
     * Used by the LWC to decide which buttons to render.
     */
    @AuraEnabled(cacheable=true)
    public static Map<String, Boolean> getPermissionState() {
        return new Map<String, Boolean>{
            'SecOps_Remediate_User' => FeatureManagement.checkPermission('SecOps_Remediate_User'),
            'SecOps_Remediate_App' => FeatureManagement.checkPermission('SecOps_Remediate_App')
        };
    }

    @AuraEnabled
    public static void revokeOauthToken(Id findingId, Id tokenId) {
        try {
            RemediationService.revokeOauthToken(findingId, tokenId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void killSession(Id findingId, Id userId, Id sessionId) {
        try {
            RemediationService.killSession(findingId, userId, sessionId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void blockConnectedApp(Id findingId, String connectedAppId) {
        try {
            RemediationService.blockConnectedApp(findingId, connectedAppId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void freezeUser(Id findingId, Id userId) {
        try {
            RemediationService.freezeUser(findingId, userId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void forcePasswordReset(Id findingId, Id userId) {
        try {
            RemediationService.forcePasswordReset(findingId, userId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
