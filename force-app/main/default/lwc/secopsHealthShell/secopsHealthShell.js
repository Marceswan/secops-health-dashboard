import { LightningElement, api } from 'lwc';

const TABS = {
    TRIAGE: 'triage',
    INVESTIGATE: 'investigate',
    POSTURE: 'posture',
    CONFIGURE: 'configure'
};

export default class SecopsHealthShell extends LightningElement {
    @api defaultTab = TABS.TRIAGE;

    activeTab = TABS.TRIAGE;

    connectedCallback() {
        if (this.defaultTab && Object.values(TABS).includes(this.defaultTab)) {
            this.activeTab = this.defaultTab;
        }
    }

    handleTabActive(event) {
        this.activeTab = event.target.value;
    }
}
