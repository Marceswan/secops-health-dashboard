import { LightningElement, api, wire } from 'lwc';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import SecopsConfirmRemediationModal from 'c/secopsConfirmRemediationModal';

import getPermissionState from '@salesforce/apex/RemediationController.getPermissionState';
import revokeOauthToken from '@salesforce/apex/RemediationController.revokeOauthToken';
import killSession from '@salesforce/apex/RemediationController.killSession';
import blockConnectedApp from '@salesforce/apex/RemediationController.blockConnectedApp';
import freezeUser from '@salesforce/apex/RemediationController.freezeUser';
import forcePasswordReset from '@salesforce/apex/RemediationController.forcePasswordReset';

/**
 * Destructive remediation control panel for a single Security_Finding__c.
 *
 * Consumed by secopsFindingDetail. Renders only the buttons the running user
 * has permission for (SecOps_Remediate_User / SecOps_Remediate_App). Each
 * button opens a confirm modal; on confirm calls the matching
 * RemediationController method and dispatches a `remediated` event so the
 * parent can refresh.
 */
export default class SecopsRemediationPanel extends LightningElement {
    @api finding;

    permissionState = {};
    busy = false;

    @wire(getPermissionState)
    wiredPerms({ data }) {
        if (data) {
            this.permissionState = data;
        }
    }

    get canRemediateUser() {
        return this.permissionState && this.permissionState.SecOps_Remediate_User === true;
    }

    get canRemediateApp() {
        return this.permissionState && this.permissionState.SecOps_Remediate_App === true;
    }

    get findingId() {
        return this.finding && this.finding.Id;
    }

    get subjectUserId() {
        return this.finding && this.finding.Subject_User__c;
    }

    get subjectAppId() {
        return this.finding && this.finding.Subject_App__c;
    }

    get connectedAppId() {
        return this.finding && this.finding.ConnectedApp_Id__c;
    }

    get hasAnyAction() {
        return this.canRemediateUser || this.canRemediateApp;
    }

    async handleRevokeToken() {
        const ok = await this.confirm(
            'Revoke OAuth Token',
            'This will revoke the linked OAuth token and mark the finding Remediated.',
            'Revoke'
        );
        if (!ok) return;
        await this.run('Revoke token', () =>
            revokeOauthToken({ findingId: this.findingId, tokenId: null })
        );
    }

    async handleKillSession() {
        const ok = await this.confirm(
            'Kill Session',
            'This will invalidate the user session(s) immediately.',
            'Kill Session'
        );
        if (!ok) return;
        await this.run('Kill session', () =>
            killSession({ findingId: this.findingId, userId: this.subjectUserId, sessionId: null })
        );
    }

    async handleBlockApp() {
        const ok = await this.confirm(
            'Block Connected App',
            'This will deactivate the connected app via the Tooling API.',
            'Block App'
        );
        if (!ok) return;
        await this.run('Block app', () =>
            blockConnectedApp({ findingId: this.findingId, connectedAppId: this.connectedAppId })
        );
    }

    async handleFreezeUser() {
        const ok = await this.confirm(
            'Freeze User',
            'This will freeze the user login. The user will be unable to sign in until thawed.',
            'Freeze'
        );
        if (!ok) return;
        await this.run('Freeze user', () =>
            freezeUser({ findingId: this.findingId, userId: this.subjectUserId })
        );
    }

    async handleForceReset() {
        const ok = await this.confirm(
            'Force Password Reset',
            'This will reset the user password and send a reset email.',
            'Reset'
        );
        if (!ok) return;
        await this.run('Force password reset', () =>
            forcePasswordReset({ findingId: this.findingId, userId: this.subjectUserId })
        );
    }

    async confirm(headline, body, actionLabel) {
        const result = await SecopsConfirmRemediationModal.open({
            size: 'small',
            headline,
            body,
            actionLabel
        });
        return result && result.confirmed === true;
    }

    async run(label, fn) {
        this.busy = true;
        try {
            await fn();
            this.dispatchEvent(
                new ShowToastEvent({
                    title: label,
                    message: 'Action completed.',
                    variant: 'success'
                })
            );
            this.dispatchEvent(new CustomEvent('remediated'));
        } catch (error) {
            const msg =
                (error && error.body && error.body.message) ||
                (error && error.message) ||
                'Unknown error';
            this.dispatchEvent(
                new ShowToastEvent({
                    title: label + ' failed',
                    message: msg,
                    variant: 'error'
                })
            );
        } finally {
            this.busy = false;
        }
    }
}
