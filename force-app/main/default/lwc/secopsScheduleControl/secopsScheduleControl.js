import { LightningElement, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getConfig from '@salesforce/apex/SecOpsScheduleController.getConfig';
import saveConfig from '@salesforce/apex/SecOpsScheduleController.saveConfig';

const DAY_OPTIONS = [
    { label: 'Sunday', value: 'Sunday' },
    { label: 'Monday', value: 'Monday' },
    { label: 'Tuesday', value: 'Tuesday' },
    { label: 'Wednesday', value: 'Wednesday' },
    { label: 'Thursday', value: 'Thursday' },
    { label: 'Friday', value: 'Friday' },
    { label: 'Saturday', value: 'Saturday' }
];

export default class SecopsScheduleControl extends LightningElement {
    dayOptions = DAY_OPTIONS;
    wiredConfigResult;
    enabled = false;
    cadenceHours = 4;
    baselineRefreshDay = 'Sunday';
    baselineRefreshHour = 2;
    isSaving = false;

    @wire(getConfig)
    wiredConfig(result) {
        this.wiredConfigResult = result;
        if (result.data) {
            this.enabled = result.data.Enabled__c === true;
            this.cadenceHours = result.data.Cadence_Hours__c != null ? result.data.Cadence_Hours__c : 4;
            this.baselineRefreshDay = result.data.Baseline_Refresh_Day__c || 'Sunday';
            this.baselineRefreshHour = result.data.Baseline_Refresh_Hour__c != null ? result.data.Baseline_Refresh_Hour__c : 2;
        }
    }

    get error() {
        return this.wiredConfigResult && this.wiredConfigResult.error;
    }

    handleEnabledChange(event) {
        this.enabled = event.target.checked;
    }

    handleCadenceChange(event) {
        this.cadenceHours = parseInt(event.target.value, 10);
    }

    handleDayChange(event) {
        this.baselineRefreshDay = event.target.value;
    }

    handleHourChange(event) {
        this.baselineRefreshHour = parseInt(event.target.value, 10);
    }

    async handleSave() {
        this.isSaving = true;
        try {
            await saveConfig({
                enabled: this.enabled,
                cadenceHours: this.cadenceHours,
                baselineRefreshDay: this.baselineRefreshDay,
                baselineRefreshHour: this.baselineRefreshHour
            });
            await refreshApex(this.wiredConfigResult);
            this.dispatchEvent(new ShowToastEvent({
                title: 'Schedule saved',
                message: 'Continuous-mode configuration updated.',
                variant: 'success'
            }));
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Save failed',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.isSaving = false;
        }
    }
}
