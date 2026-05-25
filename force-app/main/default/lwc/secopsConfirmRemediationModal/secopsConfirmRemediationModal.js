import { api } from 'lwc';
import LightningModal from 'lightning/modal';

/**
 * Generic two-button confirm modal used by the SecOps remediation panel.
 *
 * Opened via `SecopsConfirmRemediationModal.open({ headline, body, actionLabel })`.
 * Returns `{ confirmed: true }` if the user clicks Confirm, otherwise the
 * modal closes with no result (treated as cancel by the caller).
 */
export default class SecopsConfirmRemediationModal extends LightningModal {
    @api headline;
    @api body;
    @api actionLabel = 'Confirm';

    handleCancel() {
        this.close();
    }

    handleConfirm() {
        this.close({ confirmed: true });
    }
}
