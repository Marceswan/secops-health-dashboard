import { LightningElement, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import readCapability from '@salesforce/apex/CapabilityProbeController.readCapability';
import runProbe from '@salesforce/apex/CapabilityProbeController.runProbe';

export default class SecopsCapabilityStatus extends LightningElement {
    wiredResult;
    isRunning = false;

    @wire(readCapability)
    wiredCapability(result) {
        this.wiredResult = result;
    }

    get capability() {
        return this.wiredResult && this.wiredResult.data ? this.wiredResult.data : {};
    }

    get error() {
        return this.wiredResult && this.wiredResult.error;
    }

    get hasEventLogFile() {
        return this.capability.hasEventLogFile === true;
    }

    get hasRealTimeEventMonitoring() {
        return this.capability.hasRealTimeEventMonitoring === true;
    }

    // Phase 13: TSP (Transaction Security Policies) probe is not wired into the
    // backend yet; surface as locked so the UI can still show the third badge.
    get hasTransactionSecurityPolicies() {
        return false;
    }

    get eventLogFileIcon() {
        return this.hasEventLogFile ? 'utility:success' : 'utility:lock';
    }

    get eventLogFileVariant() {
        return this.hasEventLogFile ? 'success' : 'inverse';
    }

    get rtemIcon() {
        return this.hasRealTimeEventMonitoring ? 'utility:success' : 'utility:lock';
    }

    get rtemVariant() {
        return this.hasRealTimeEventMonitoring ? 'success' : 'inverse';
    }

    get tspIcon() {
        return this.hasTransactionSecurityPolicies ? 'utility:success' : 'utility:lock';
    }

    get tspVariant() {
        return this.hasTransactionSecurityPolicies ? 'success' : 'inverse';
    }

    get lastProbedLabel() {
        const ts = this.capability.lastProbed;
        return ts ? new Date(ts).toLocaleString() : 'Never';
    }

    async handleRunProbe() {
        this.isRunning = true;
        try {
            await runProbe();
            await refreshApex(this.wiredResult);
            this.dispatchEvent(new ShowToastEvent({
                title: 'Probe complete',
                message: 'Capability snapshot refreshed.',
                variant: 'success'
            }));
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Probe failed',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.isRunning = false;
        }
    }
}
