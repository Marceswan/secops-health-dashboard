import { LightningElement, api } from 'lwc';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import acknowledgeBulk from '@salesforce/apex/WorkflowController.acknowledgeBulk';
import dismissBulk from '@salesforce/apex/WorkflowController.dismissBulk';

export default class SecopsBulkActionBar extends LightningElement {
    @api selectedIds = [];
    busy = false;
    showDismissModal = false;
    dismissReason = '';
    boundEscHandler;

    get count() { return this.selectedIds ? this.selectedIds.length : 0; }
    get hasSelection() { return this.count > 0; }
    get acknowledgeLabel() { return `Acknowledge selected (${this.count})`; }
    get dismissLabel() { return `Dismiss selected (${this.count})`; }
    get disabled() { return this.busy || !this.hasSelection; }

    async handleAcknowledge() {
        if (!this.hasSelection) return;
        this.busy = true;
        try {
            await acknowledgeBulk({ findingIds: this.selectedIds });
            this.dispatchEvent(new ShowToastEvent({
                title: 'Findings acknowledged',
                message: `${this.count} finding(s) updated.`,
                variant: 'success'
            }));
            this.fireApplied('acknowledge');
        } catch (error) {
            this.showError('Bulk acknowledge failed', error);
        } finally {
            this.busy = false;
        }
    }

    openDismissModal() {
        if (!this.hasSelection) return;
        this.dismissReason = '';
        this.showDismissModal = true;
        this.boundEscHandler = (e) => {
            if (e.key === 'Escape') this.closeDismissModal();
        };
        window.addEventListener('keyup', this.boundEscHandler);
    }

    closeDismissModal() {
        this.showDismissModal = false;
        if (this.boundEscHandler) {
            window.removeEventListener('keyup', this.boundEscHandler);
            this.boundEscHandler = null;
        }
    }

    disconnectedCallback() {
        if (this.boundEscHandler) {
            window.removeEventListener('keyup', this.boundEscHandler);
            this.boundEscHandler = null;
        }
    }

    handleReasonChange(event) {
        this.dismissReason = event.target.value;
    }

    async handleDismissConfirm() {
        if (!this.dismissReason) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Reason required',
                message: 'Provide a reason before dismissing.',
                variant: 'warning'
            }));
            return;
        }
        this.busy = true;
        try {
            await dismissBulk({ findingIds: this.selectedIds, reason: this.dismissReason });
            this.dispatchEvent(new ShowToastEvent({
                title: 'Findings dismissed',
                message: `${this.count} finding(s) updated.`,
                variant: 'success'
            }));
            this.closeDismissModal();
            this.fireApplied('dismiss');
        } catch (error) {
            this.showError('Bulk dismiss failed', error);
        } finally {
            this.busy = false;
        }
    }

    fireApplied(action) {
        this.dispatchEvent(new CustomEvent('bulkactionapplied', {
            detail: { action, count: this.count }
        }));
    }

    showError(title, error) {
        this.dispatchEvent(new ShowToastEvent({
            title,
            message: error && error.body ? error.body.message : (error && error.message ? error.message : 'Unknown error'),
            variant: 'error'
        }));
    }
}
