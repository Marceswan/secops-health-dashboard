import { LightningElement, wire } from 'lwc';
import getAppInventorySummary from '@salesforce/apex/PostureController.getAppInventorySummary';

export default class SecopsAppInventoryCard extends LightningElement {
    wiredResult;

    @wire(getAppInventorySummary)
    wiredSummary(result) {
        this.wiredResult = result;
    }

    get summary() {
        return this.wiredResult && this.wiredResult.data ? this.wiredResult.data : {};
    }

    get hasError() {
        return this.wiredResult && this.wiredResult.error;
    }

    get totalApps() {
        return this.summary.totalApps != null ? this.summary.totalApps : '-';
    }

    get newIn30Days() {
        return this.summary.newIn30Days != null ? this.summary.newIn30Days : '-';
    }

    get broadScopeCount() {
        return this.summary.broadScopeCount != null ? this.summary.broadScopeCount : '-';
    }

    get staleCount() {
        return this.summary.staleCount != null ? this.summary.staleCount : '-';
    }
}
