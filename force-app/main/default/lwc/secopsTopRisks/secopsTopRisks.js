import { LightningElement, wire } from 'lwc';
import getTopRisks from '@salesforce/apex/PostureController.getTopRisks';

export default class SecopsTopRisks extends LightningElement {
    wiredUsers;
    wiredApps;

    @wire(getTopRisks, { dimension: 'user', limitSize: 10 })
    wiredTopUsers(result) {
        this.wiredUsers = result;
    }

    @wire(getTopRisks, { dimension: 'app', limitSize: 10 })
    wiredTopApps(result) {
        this.wiredApps = result;
    }

    get users() {
        return this.wiredUsers && this.wiredUsers.data ? this.wiredUsers.data : [];
    }

    get apps() {
        return this.wiredApps && this.wiredApps.data ? this.wiredApps.data : [];
    }

    get hasUsers() {
        return this.users.length > 0;
    }

    get hasApps() {
        return this.apps.length > 0;
    }
}
