# SecOps Health — Deploy & Metadata Learnings

Running log of metadata gotchas, deploy traps, and platform constraints we've hit on this project.
Update this file every time we resolve a non-obvious issue so we don't burn time on it again.

---

## How to use this file

- Add a new entry **at the top of the relevant section** when you finish debugging something.
- Lead with the **symptom** (the error text you'd Google), then the **rule**, then the **fix**.
- Keep entries terse — one paragraph each is fine. Link to the file you fixed.
- If a fix differs between API versions or org types, say so.

---

## Deploy-time errors

### `UNKNOWN_EXCEPTION: An unexpected error occurred. Please include this ErrorId ...` with `numberComponentErrors: 0`

**Symptom:** Full-project deploy fails in <2s during "Preparing" or "Waiting for org to respond". The CLI shows `Status: Failed`, `0 component errors`, and an opaque ErrorId. No per-file message anywhere.

**Rule:** This is a manifest-level rejection. The server is refusing to parse the package before it gets to component validation. The actual culprit is almost always a single malformed metadata file (invalid XML schema, unsupported element for the metadata type, unsupported feature on the target org), but rollback-on-error suppresses any per-component output.

**Diagnostic:** Don't keep retrying the full deploy. Bisect by deploying one directory at a time (`--source-dir force-app/main/default/<type>`) with `--test-level NoTestRun`. The bad file will show a real error once isolated. Common offenders we've seen on this repo:

- `NamedCredential` with invalid `<calloutOptions>` wrapper (see below).
- `Security_Finding_Archive__b` Big Object on a Dev Edition org that lacks the Big Objects feature.

When you find the file, fix it and re-run. The UNKNOWN_EXCEPTION goes away once the offending file is valid.

### `NamedCredential` parse error: `Element {…}calloutOptions invalid at this location`

**Symptom:** `NamedCredential / Error parsing file: Element {http://soap.sforce.com/2006/04/metadata}calloutOptions invalid at this location in type NamedCredential`.

**Rule:** Legacy `NamedCredential` (the only type available at API 62.0 in this project) does **not** wrap callout flags in a `<calloutOptions>` element. The flags `allowMergeFieldsInBody`, `allowMergeFieldsInHeader`, and `generateAuthorizationHeader` must be **direct children** of `<NamedCredential>`. The `<calloutOptions>` wrapper belongs to the newer External Credential / Permission-Set-Mapping model, not classic NamedCredential XML.

**Fix:** Flatten the structure and dedupe any flag that appears both inside the wrapper and at the top level (we had two copies of `generateAuthorizationHeader`).

**File touched:** `force-app/main/default/namedCredentials/SecOpsToolingApi.namedCredential-meta.xml`

### Big Objects on Developer Edition

**Symptom:** Full deploy fails as `UNKNOWN_EXCEPTION` with no component errors when the manifest includes a `__b` object.

**Rule:** Big Objects require the Big Objects feature, which standard Developer Edition orgs (the orgfarm `*-dev-ed.develop.my.salesforce.com` ones, including our `chartbuddy` alias) do not have. The server rejects the entire deploy at parse time rather than skipping the unsupported type.

**Fix:** Move the Big Object metadata out of `force-app/` to `archived_files/` (per the project rule: never delete metadata) and strip any Apex code that references it. Don't leave an empty `bigObjects/` directory in `force-app/` either — Salesforce sometimes catalogs that as a metadata-type intent and fails the deploy with a similar opaque error.

**Files touched:**
- `archived_files/objects/Security_Finding_Archive__b/` (moved from `force-app/main/default/objects/`)
- `archived_files/classes/FindingArchiver.cls(+_Test).cls` (moved from `force-app/main/default/classes/`)
- `force-app/main/default/classes/SecOpsScheduledCleanup.cls` — removed the FindingArchiver batch invocation; left a TODO for the replacement archive mechanism.

---

## Custom Field gotchas

### Lookup to User cannot have `<deleteConstraint>Cascade</deleteConstraint>` or `<deleteConstraint>Restrict</deleteConstraint>`

**Symptom:** `Cannot add a lookup relationship child with cascade or restrict options to User`.

**Rule:** User is a special object. The only valid delete behavior for a custom lookup to User is `SetNull` (the default). Cascade is not allowed because deleting a user would mass-delete arbitrary related records; Restrict is not allowed because Salesforce reserves user deactivation/deletion semantics.

**Fix:** Remove the `<deleteConstraint>` element entirely. It defaults to SetNull.

**Files touched:** `Action_Audit__c/fields/Actor__c.field-meta.xml`, `User_Baseline__c/fields/User__c.field-meta.xml`

### Required lookup + no delete constraint = "must specify either cascade delete or restrict delete"

**Symptom:** `field integrity exception: unknown (must specify either cascade delete or restrict delete for required lookup foreign key)`.

**Rule:** When a lookup is `<required>true</required>`, the platform forces you to declare a delete constraint (Cascade or Restrict) so the orphan case is explicit. The contradiction we hit on this project: lookups to **User** can be neither Cascade nor Restrict, AND they can't be required. Pick one of:

1. `<required>false</required>` + no `<deleteConstraint>` (defaults to SetNull). Enforce required-ness in Apex/Flow at the application layer.
2. Keep it required and make it a Master-Detail (cascade is implicit), but Master-Detail isn't valid for User lookups either.

In practice for lookups to User, option 1 is the only path.

**Files touched (same files as above, second pass):** flipped `<required>true</required>` → `<required>false</required>` on Actor__c, Finding__c (Action_Audit), and User__c (User_Baseline). Added a TODO to enforce required-ness via Apex on the relevant controllers/services.

### Lookup with `<deleteConstraint>Cascade</deleteConstraint>` on a custom object — "please contact salesforce.com"

**Symptom:** `If you want to cascade delete, please contact salesforce.com`.

**Rule:** Cascade delete on a lookup (not master-detail) requires Salesforce Support to enable the org-level toggle that allows it. Master-Detail cascades automatically without this toggle.

**Fix options:**
1. Remove the `<deleteConstraint>Cascade</deleteConstraint>` line (defaults to SetNull — orphans the child on parent delete). Preferred for audit-trail-style children where you want history retained.
2. Convert to Master-Detail if cascade is genuinely required and the sharing/reparent implications are acceptable.
3. File a support case to enable cascade-delete on lookups for the org (rarely worth it).

We chose option 1 for `Action_Audit__c.Finding__c` so the audit trail survives finding deletion.

### Custom Metadata Type picklists must be `<restricted>true</restricted>`

**Symptom:** `Non-strict picklists are not supported on this object` on a `__mdt.<field>` deploy.

**Rule:** Custom Metadata Type picklist fields **must** be restricted (strict). You cannot allow ad-hoc values on a CMDT picklist the way you can on a standard custom object picklist.

**Fix:** Change `<restricted>false</restricted>` → `<restricted>true</restricted>` inside the `<valueSetDefinition>`. If business needs free-text, change the field type to Text instead.

**File touched:** `Detection_Rule__mdt/fields/Run_Frequency__c.field-meta.xml`

### Rollup Summary with `count` operation — do not specify `<summarizedField>`

**Symptom:** `Custom Field Definition ID: bad value for restricted picklist field: Id` on a Summary field.

**Rule:** `<summarizedField>` is only valid for `sum`, `min`, `max`, `avg`. For `<summaryOperation>count</summaryOperation>`, the `<summarizedField>` element must be **omitted**. The platform's error message about a "restricted picklist" is misleading — it's actually rejecting the combination.

**Fix:** Remove the `<summarizedField>...</summarizedField>` line entirely for count rollups.

**File touched:** `SecOps_Scan_Run__c/fields/Findings_Created__c.field-meta.xml`

### Formula fields cannot have `<unique>` or `<externalId>`

**Symptom (1):** `Can not specify unique for CustomFields that have a formula`.
**Symptom (2):** `Can not specify externalId for CustomFields that have a formula`.

**Rule:** Formula fields are computed at read time. The platform won't let you mark them `unique` (no write-time enforcement) **and** won't let you mark them `externalId` (the prior assumption that externalId on formulas was OK for indexing is wrong — it isn't). If you genuinely need a unique compound key or an indexed external ID, materialize the value into a real Text field via Apex/Flow at write time, and put `unique`/`externalId` on the real field.

**Fix:** Remove **both** `<unique>true</unique>` and `<externalId>true</externalId>` from the formula field. If indexing is needed, file a custom-index support case for the formula or materialize the value.

**Files touched:** `Security_Event__c/fields/Composite_Key__c.field-meta.xml`, `Security_Finding__c/fields/Composite_Key__c.field-meta.xml`

### Picklist fields can't have `<trackTrending>` or `<externalId>`

**Symptom:** `Invalid data type.` — a deeply unhelpful message from the platform pointing at a line that isn't actually the offending element.

**Rule:** Picklists support a smaller set of metadata elements than other types. Two specifically reject: `<trackTrending>` (only valid on numeric/date) and `<externalId>` (only valid on text/number). The platform reports `Invalid data type.` for both, and the line:column pointer often lags by a line or two — don't trust it literally.

**Fix:** Remove both `<trackTrending>` and `<externalId>` from any picklist field-meta. We had to make two passes on `Baseline_Refresh_Day__c`: first to remove `trackTrending`, then to remove `externalId` after the second deploy attempt surfaced the same error message.

**File touched:** `SecOps_Schedule_Config__c/fields/Baseline_Refresh_Day__c.field-meta.xml`

---

### Custom Settings do not support Picklist fields

**Symptom:** `Invalid data type.` on a picklist field defined on what looks like a normal custom object. The line:column pointer is unhelpful and usually points at `<valueSet>`.

**Rule:** If the parent object has `<customSettingsType>Hierarchy</customSettingsType>` (or `List`), it's a Custom Setting, not a CustomObject. Custom Settings only allow these field types: Checkbox, Currency, Date, Date/Time, Email, Number, Percent, Phone, Text, Text Area, URL. Picklists are **not** in that list and the platform reports them as "Invalid data type" without saying why.

**Diagnostic check:** Before assuming the field-meta is malformed, look at the parent `.object-meta.xml` for a `<customSettingsType>` element. If present, you're on a Custom Setting and picklist/lookup/master-detail/formula fields will all be rejected.

**Fix:** Either convert the field to Text and enforce allowed values in Apex/Flow, or migrate the configuration off Custom Settings to Custom Metadata Types (which DO support picklists, just with `<restricted>true</restricted>` — see the CMDT rule above).

**File touched:** `SecOps_Schedule_Config__c/fields/Baseline_Refresh_Day__c.field-meta.xml` — converted from Picklist (Sunday..Saturday) to Text(10) with a description noting the expected values.

---

## Formula gotchas

### Picklist fields in formulas need `TEXT()` for string operations

**Symptom:** `Field <X>__c is a picklist field. Picklist fields are only supported in certain functions.`

**Rule:** A bare picklist reference inside `&` concatenation or most string functions is invalid. Picklists must be wrapped in `TEXT(<picklist>)` to become a string. The opposite mistake (wrapping a non-picklist in TEXT) produces the next error below.

**Fix:** Wrap every picklist reference in `TEXT(...)` when used in a Text formula.

**Example:** `Event_Type__c & "|" & ...` → `TEXT(Event_Type__c) & "|" & ...`.

**File touched:** `Security_Event__c/fields/Composite_Key__c.field-meta.xml`

### Formulas cannot reference Long Text Area fields — `LEFT()` doesn't help

**Symptom:** `You referenced an unsupported field type called "Long Text Area" using the following field: <X>__c`.

**Rule:** Formula fields cannot reference Long Text Area fields at all. Not directly, not via `LEFT()` or any other function — the type itself is unsupported in the formula compiler regardless of how it's consumed. Comments in legacy code that say "we use LEFT() because formulas don't support substring of long-text" are wishful thinking; the field type isn't supported at any length.

**Fix options:**
1. Drop the Long Text reference from the formula. Lose that part of the value.
2. Materialize the desired value (e.g. a hash, prefix, or truncated copy) into a real Text field via Apex/Flow on insert/update. Reference that materialized field from the formula instead.

We took option 1 for `Security_Event__c.Composite_Key__c` and left a TODO to materialize a hash of `Source_Json__c` for real idempotency.

**File touched:** `Security_Event__c/fields/Composite_Key__c.field-meta.xml`

### `TEXT()` doesn't accept Lookup fields — use `CASESAFEID()`

**Symptom:** `Incorrect parameter type for function 'TEXT()'. Expected Number, Date, Date/Time, Picklist, received Lookup(User)`.

**Rule:** `TEXT()` only accepts Number, Date, Date/Time, and Picklist. For Lookup or Master-Detail fields, you have two options:

1. Reference the field directly — Lookup fields are already string-coerced inside `&` concatenation, so `MyLookup__c & "|"` works for the 15-char case-sensitive ID.
2. Use `CASESAFEID(MyLookup__c)` for the canonical 18-char ID (preferred for uniqueness/comparison since it survives case-folding).

**Fix:** Replace `TEXT(Subject_User__c)` with `CASESAFEID(Subject_User__c)` in compound-key formulas.

**File touched:** `Security_Finding__c/fields/Composite_Key__c.field-meta.xml`

---

## Object-level gotchas

### `<sharingModel>Private</sharingModel>` is invalid on an object with a Master-Detail field

**Symptom:** `Cannot set sharingModel to Private on a CustomObject with a MasterDetail relationship field`.

**Rule:** A child of a Master-Detail relationship **inherits** sharing from the parent. Its `sharingModel` MUST be `ControlledByParent`. The `externalSharingModel` must also be `ControlledByParent` (or `Private` is accepted in some API versions, but `ControlledByParent` is consistent and safe).

**Fix:** Change both `<sharingModel>` and `<externalSharingModel>` to `ControlledByParent` on the child object's `.object-meta.xml`.

**File touched:** `Security_Finding__c/Security_Finding__c.object-meta.xml` (it has `Scan_Run__c` as a Master-Detail).

---

## List View gotchas

### `Could not resolve list view column: Name`

**Symptom:** Deploy of a ListView reports `Could not resolve list view column: Name`, even though the object has a Name field (autonumber or otherwise).

**Rule:** Two distinct causes:

1. **Cascading resolution failure.** If any later `<columns>` element references a field that doesn't exist, the platform sometimes reports the first column ("Name") as unresolved. Look for non-existent fields in the same `<columns>` list (we had `Title__c` and `Detected_At__c` referenced but not defined on `Security_Finding__c`).
2. **Casing.** In some API versions / object configurations, the standard Name column must be written as `<columns>NAME</columns>` (all caps) rather than `<columns>Name</columns>`. We changed to `NAME` for safety along with removing the missing custom fields.

**Fix:** Remove any `<columns>` entries that point to fields not defined on the object, and use `NAME` (uppercase) for the standard Name column.

**File touched:** `Security_Finding__c/listViews/All_Open_Findings.listView-meta.xml`

---

---

## Apex / SOQL gotchas

### `LoginHistory.Status` and `SetupAuditTrail.Display` cannot be in WHERE clauses

**Symptom:** `field 'Status' can not be filtered in a query call` or `field 'Display' can not be filtered in a query call`.

**Rule:** Some standard fields on system objects are selectable but not filterable. The platform indexes that we can hit don't include these fields. Most common offenders we've found:

- `LoginHistory.Status` (used in BaselineEngine and Rule_Baseline*)
- `SetupAuditTrail.Display` (used in Rule_MfaDisabledForUser, Rule_SessionTimeoutExtended)

**Fix:** Move the filter out of SOQL and into post-query Apex. Pull the rows you need with a filterable field (e.g. `CreatedDate >= :cutoff`, `UserId = :userId`), then `continue` past rows that don't match the unfilterable predicate.

**Files touched:** `BaselineEngine.cls`, `UserBaselineRefresh.cls`, `Rule_BaselineNewCountry.cls`, `Rule_BaselineNewIp24.cls`, `Rule_BaselineOffHours.cls`, `Rule_MfaDisabledForUser.cls`, `Rule_SessionTimeoutExtended.cls`.

### `COUNT_DISTINCT(UserId)` not supported on `OauthToken`

**Symptom:** `field UserId does not support aggregate operator COUNT_DISTINCT`.

**Rule:** Not every Lookup/Id field supports `COUNT_DISTINCT` aggregation in SOQL. `OauthToken.UserId` is one that doesn't. The platform doesn't document which fields aggregate cleanly; we discover it deploy-by-deploy.

**Fix:** Pull the raw rows in a single SOQL and aggregate distinct users per group using an Apex `Map<String, Set<Id>>`. This adds heap and execution time vs. a SOQL aggregate, but works.

**File touched:** `Rule_NewAppSurge.cls`

### `when` is a reserved Apex keyword (since API 51 / Apex switch)

**Symptom:** `Identifier name is reserved: when`.

**Rule:** When `switch on` was added to Apex, `when` became reserved. Existing code that used `when` as a variable, parameter, or method name now fails to compile.

**Fix:** Rename to something non-reserved (`actionAt`, `whenValue`, `evt`, whatever fits semantics). Use word-boundary regex to do it across a file, but watch for English `when` in comments and fix those back.

**Files touched:** `RemediationService.cls`, `WorkflowController.cls`

### Field type drift — `Signals_Evaluated__c` was declared as Text(255) but used as Integer everywhere

**Symptom:** Cascading `Illegal assignment from Integer to String` errors across many classes.

**Rule:** When the metadata field type doesn't match the Apex usage type, you get a confusing compile error. The fix usually lives in the field-meta.xml, not the Apex.

**Diagnostic:** When a single error appears in many "Dependent class is invalid and needs recompilation" messages, walk back to the root class. Inspect each assigned field's type in its `.field-meta.xml`. The field type, not the consumer, is usually wrong.

**Fix:** Change the offending field's `<type>` to match how it's used. `Signals_Evaluated__c` was changed from Text(255) to Number(9,0). This is safe in fresh orgs but destructive on populated production fields.

**File touched:** `SecOps_Scan_Run__c/fields/Signals_Evaluated__c.field-meta.xml`

### Read-only fields (formulas, rollups) cannot be assigned in Apex DML

**Symptom:** `Field is not writeable: <object>.<field>` on insert/update.

**Rule:** Any field whose value the platform computes — Formula fields, Rollup Summary fields, Autonumber fields, system audit fields — cannot be set in Apex constructors or via assignment. Tests that pre-populate these to control assertions need to be rewritten.

**Fix:** Strip the assignment. For tests that asserted a specific count from a rollup, either insert the actual child rows or update the assertion to reflect the post-DML rollup state.

**Files touched:** `EngagementSummaryPdfController_Test.cls`, `PostureController_Test.cls`, `TestDataFactory.cls`, `SetupAuditIngest.cls`, `ScanRunService.cls`, `ScanRunService_Test.cls`, `SecOpsScheduledRunner_Test.cls`

### `Auth.SessionManagement.invalidateSessions` takes `List<String>`, not `List<Id>`

**Symptom:** `Method does not exist or incorrect signature: void invalidateSessions(List<Id>) from the type Auth.SessionManagement`.

**Rule:** The platform method signature is `invalidateSessions(List<String> sessionIds)`. Even though `Id` auto-coerces to `String` in many Apex contexts, the method overload resolution refuses it.

**Fix:** Build a `List<String>` and `String.valueOf(idValue)` on each element before calling.

**File touched:** `RemediationService.cls`

### Multi-picklist filters must use `INCLUDES` / `EXCLUDES`, not `LIKE` or `=`

**Symptom:** `invalid operator on multipicklist field`.

**Rule:** For SOQL on `MultiselectPicklist` fields, the only valid operators are `INCLUDES('a','b')` and `EXCLUDES('a','b')`. The values list inside parens uses semicolons in the actual stored string but commas in SOQL.

**Fix:** Replace `WHERE Risk_Flags__c LIKE '%Broad Scope%'` with `WHERE Risk_Flags__c INCLUDES ('Broad Scope')`.

**File touched:** `PostureController.cls`

### Three different field-name conventions on the same Custom Metadata Type

**Symptom:** A customMetadata `.md-meta.xml` record references fields that don't exist on the parent `__mdt`, and an Apex controller references a third, also-nonexistent set of names. All three were authored from the same idea, by different generations or AI passes.

**Rule:** Trust the `__mdt/fields/` directory as the source of truth — those `.field-meta.xml` files are the actual schema. The customMetadata record (`.md-meta.xml`) and any Apex referencing the type must be aligned to those exact API names.

**Fix:** Read `force-app/main/default/objects/<TypeName>__mdt/fields/` to enumerate the real fields, then update everything else to match. We had: actual `EventLogFile_Available__c` / `RealTimeEventMonitoring_Available__c` / `Last_Probed__c`, vs. controller using `Has_Event_Log_File__c` / `Has_Real_Time_Event_Monitoring__c` / `Last_Probed_At__c`, vs. the record file using `Enable_Event_Stream__c` / `Enable_Real_User_Monitoring__c` / `Has_Shield_Event_Monitoring__c`. Standardized on the field-meta names.

**Files touched:** `CapabilityProbeController.cls`, `MetadataService.cls`, `customMetadata/SecOps_Capability.Current.md-meta.xml`

---

## FlexiPage gotchas

### Each `<itemInstances>` block can only contain ONE `<componentInstance>`

**Symptom:** `Element componentInstance is duplicated at this location in type ItemInstance`.

**Rule:** A `<flexiPageRegions>` block holds an ordered list of `<itemInstances>` blocks — and EACH `<itemInstances>` wraps EXACTLY ONE `<componentInstance>`. Multiple components in a region means multiple `<itemInstances>`, not multiple components inside one.

**Fix:** Split sibling components into their own `<itemInstances>` wrappers. Visual order is preserved by document order.

**Files touched:** `SecOps_Configure.flexipage-meta.xml`, `Security_Finding_Record_Page.flexipage-meta.xml`

### `flexipage:appHomeTemplateDesktop_3` and other versioned template names don't exist

**Symptom:** `Template flexipage:appHomeTemplateDesktop_3 doesn't exist.`

**Rule:** Some template names that show up in retrieves from older orgs have version suffixes that don't actually deploy. Stick with documented templates like `flexipage:defaultAppHomeTemplate` (single region named `main`) or `flexipage:recordHomeTemplateDesktop` (multi-region for record pages).

**Fix:** Replace the bogus template name. If you need multiple regions on an app page but the template only has `main`, consolidate components into the `main` region.

**File touched:** `SecOps_Investigate.flexipage-meta.xml`

### Region names must match what the chosen template exposes

**Symptom:** `The 'header' region (type Region) doesn't exist.`

**Rule:** Templates define a fixed set of named regions (typically `header`, `main`, `sidebar`, etc.). If your XML references a region the template doesn't have, deploy fails. Common offenders: `header` and `sidebar` aren't part of `flexipage:defaultAppHomeTemplate` — only `main` is.

**Fix:** Either change the template to one that exposes the region you need, or drop the extra `<flexiPageRegions>` blocks and put everything under the supported region (usually `main`).

**File touched:** `SecOps_Triage.flexipage-meta.xml`

### "We couldn't retrieve the design time component information for component X"

**Symptom:** This vague message on Lightning record pages, often pointing to platform components like `flexipage:highlightsPanel`, `flexipage:relatedListContainer`, `runtime_chatter:feedContainer`, or `runtime_sales_activities:activitiesComposite`.

**Rule:** Standard FlexiPage components are gated behind feature/license combinations that vary by org type. Developer Edition orgs (like `chartbuddy`) often lack Chatter, Sales-app components, or even Highlights Panel/Related Lists at deploy time. The error reads as a configuration issue but is really a feature-availability issue.

**Fix:** Strip the gated components from the FlexiPage. Test in the target org; bring components back only when the org has the right features enabled. For a record page that needs to deploy across many org types, keep only first-party (custom `c:`) components.

**File touched:** `Security_Finding_Record_Page.flexipage-meta.xml` — reduced to only `c:secopsFindingDetail`.

---

## Permission Set dependency chains

### `ManageUsers` requires 12 other admin permissions

**Symptom:** `Permission ManageUsers depends on permission(s): AssignPermissionSets, DelegatedTwoFactor, FreezeUsers, ManageInternalUsers, ManageIpAddresses, ManageLoginAccessPolicies, ManagePasswordPolicies, ManageProfilesPermissionsets, ManageRoles, ManageSharing, MonitorLoginHistory, ViewAllUsers`.

**Rule:** Several user-administration permissions only deploy together as a group. When you enable one, the platform requires the rest of the bundle to be in the same permission set XML.

**Fix:** Add all 12 dependent permissions to the `<userPermissions>` block. Order them alphabetically for diff readability.

**File touched:** `SecOps_Destructive_Remediation.permissionset-meta.xml` (also needed `ViewRoles` and `ViewSetup` for `ResetPasswords`).

### `<allowDelete>` requires `<allowEdit>` on object permissions

**Symptom:** `Permission Delete OauthToken depends on permission(s): Edit OauthToken`.

**Rule:** You cannot grant Delete without Edit on a given object. The platform treats Delete as a strict superset of Edit. Even if your business case is "delete but don't modify," that's not expressible in a permission set.

**Fix:** Set both `<allowEdit>true</allowEdit>` and `<allowDelete>true</allowDelete>` for the object permission.

**File touched:** `SecOps_Destructive_Remediation.permissionset-meta.xml` — OauthToken.

---

## Deploy bisection patterns

### Empty package-type directories trigger UNKNOWN_EXCEPTION on full deploys

**Symptom:** Full `--source-dir force-app` deploy fails with `UNKNOWN_EXCEPTION` and 0 components processed, while every individual sub-deploy of the same content succeeds.

**Rule:** Salesforce's package zip includes any subdirectory of `force-app/main/default/` that matches a known metadata type name (`bigObjects/`, `settings/`, `labels/`, `staticresources/`, `layouts/`, `connectedApps/`, `triggers/`). If those directories are empty, the platform still catalogs them as a deploy-time intent for that metadata type and rejects the package if the type isn't available on the target org.

**Fix:** Remove the empty directories (`rmdir force-app/main/default/<typeName>`). Empty dirs aren't files, so the "never delete" project rule doesn't apply — they're structural noise. Keep them only when they actually contain files.

### When the full deploy fails but individual layers succeed

**Diagnostic:** Salesforce's manifest-parse stage can reject a package for a reason it doesn't surface as a per-component error. When `--source-dir force-app` fails with UNKNOWN_EXCEPTION at 0/N components but each `--source-dir force-app/main/default/<one-folder>` succeeds:

1. Look for empty directories at the top level (above).
2. Try combining two layers at a time to find the conflicting pair.
3. Check for picklist field schema changes that the platform hasn't published yet (e.g., changing `restricted` from false to true on a CMT picklist — the field-def deploys but CustomMetadata records that reference values may briefly fail until the picklist is fully active).
4. If only CustomMetadata records are still rejected, retry later, or apply them via Setup UI instead.

We hit pattern #4 on this deploy. The 24 Detection_Rule__mdt + SecOps_Capability__mdt records did not deploy in this session despite all referenced fields and picklist values being valid in the org.

---

## Project conventions worth remembering

- **Never delete metadata.** Anything that has to leave `force-app/` moves to `archived_files/` at the project root. Preserves history outside git in case we need it back.
- **Always deploy with explicit `--target-org <alias>`.** Don't rely on the default. Confirm the alias and instance URL in chat before deploying.
- **Default deploy command for this project:** `sf project deploy start --source-dir force-app --target-org <alias> --test-level RunLocalTests --wait 60`. Use `NoTestRun` only for diagnostic sub-deploys when isolating a parse failure.
- **Org-tracker status:** `chartbuddy` is a Developer Edition org (orgfarm), not a sandbox. It is the current target for clean-room deploys. Big Objects, Shield Platform Encryption, and other licensed features are **not available** on this org.
