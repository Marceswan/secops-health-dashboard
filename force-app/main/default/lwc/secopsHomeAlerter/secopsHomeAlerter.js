import { LightningElement, wire } from 'lwc';
import { NavigationMixin } from 'lightning/navigation';
import { refreshApex } from '@salesforce/apex';
import getCriticalCount from '@salesforce/apex/FindingQueueController.getCriticalCount';

const POLL_INTERVAL_MS = 30000;

export default class SecopsHomeAlerter extends NavigationMixin(LightningElement) {
    wiredCountResult;
    pollHandle;

    @wire(getCriticalCount)
    wiredCount(result) {
        this.wiredCountResult = result;
    }

    get count() {
        return this.wiredCountResult && this.wiredCountResult.data != null ? this.wiredCountResult.data : 0;
    }

    get hasAlerts() {
        return this.count > 0;
    }

    get badgeVariant() {
        return this.hasAlerts ? 'inverse' : 'base';
    }

    get cardIcon() {
        return this.hasAlerts ? 'utility:warning' : 'utility:shield';
    }

    get headline() {
        return this.hasAlerts
            ? `${this.count} critical finding${this.count === 1 ? '' : 's'} need attention`
            : 'No critical findings';
    }

    connectedCallback() {
        this.pollHandle = setInterval(() => {
            if (this.wiredCountResult) {
                refreshApex(this.wiredCountResult);
            }
        }, POLL_INTERVAL_MS);
    }

    disconnectedCallback() {
        if (this.pollHandle) {
            clearInterval(this.pollHandle);
            this.pollHandle = null;
        }
    }

    handleClick() {
        this[NavigationMixin.Navigate]({
            type: 'standard__navItemPage',
            attributes: {
                apiName: 'SecOps_Triage'
            }
        });
    }
}
