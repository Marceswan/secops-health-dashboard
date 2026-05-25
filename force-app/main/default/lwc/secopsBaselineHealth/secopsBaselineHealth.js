import { LightningElement, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getHealthStats from '@salesforce/apex/BaselineEngine.getHealthStats';
import refreshAllNow from '@salesforce/apex/BaselineEngine.refreshAllNow';

export default class SecopsBaselineHealth extends LightningElement {
    wiredResult;
    isRefreshing = false;

    @wire(getHealthStats)
    wiredStats(result) {
        this.wiredResult = result;
    }

    get stats() {
        return this.wiredResult && this.wiredResult.data ? this.wiredResult.data : {};
    }

    get error() {
        return this.wiredResult && this.wiredResult.error;
    }

    get totalUsers() {
        return this.stats.totalUsers != null ? this.stats.totalUsers : 0;
    }

    get usersWithBaseline() {
        return this.stats.usersWithBaseline != null ? this.stats.usersWithBaseline : 0;
    }

    get usersWithoutBaseline() {
        return this.stats.usersWithoutBaseline != null ? this.stats.usersWithoutBaseline : 0;
    }

    get oldestRefreshLabel() {
        const ts = this.stats.oldestRefresh;
        return ts ? new Date(ts).toLocaleString() : 'Never';
    }

    get newestRefreshLabel() {
        const ts = this.stats.newestRefresh;
        return ts ? new Date(ts).toLocaleString() : 'Never';
    }

    async handleRefreshAll() {
        this.isRefreshing = true;
        try {
            await refreshAllNow();
            this.dispatchEvent(new ShowToastEvent({
                title: 'Refresh enqueued',
                message: 'Baselines will refresh in the background.',
                variant: 'success'
            }));
            await refreshApex(this.wiredResult);
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Refresh failed',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.isRefreshing = false;
        }
    }
}
