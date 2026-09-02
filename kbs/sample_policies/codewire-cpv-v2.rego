package policy

import rego.v1

# Storage-specific policy for Codewire confidential persistent volumes. The
# corresponding KBS deployment must select the `codewire-cpv-v2` AS policy
# family, so a generic or client-selected appraisal cannot authorize access.
default allow := false

environment_id_pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
storage_manifest_tag_pattern := "^sha256-[0-9a-f]{64}$"

approved_appraisal(appraisal) if {
	appraisal["ear.status"] == "affirming"
	appraisal["ear.appraisal-policy-id"] == "codewire-cpv-v2"
}

unapproved_appraisal if {
	some _, appraisal in input.submods
	not approved_appraisal(appraisal)
}

all_appraisals_approved if {
	count(input.submods) > 0
	not unapproved_appraisal
}

measured_cpv_claims := claims if {
	all_appraisals_approved

	cpu := input.submods.cpu0
	evidence := cpu["ear.veraison.annotated-evidence"]
	evidence.snp != null
	regex.match("^[0-9a-f]{64}$", evidence.init_data)

	claims := evidence.init_data_claims
	regex.match(environment_id_pattern, claims.codewire_workspace_storage_key_id)
	regex.match(storage_manifest_tag_pattern, claims.codewire_workspace_storage_manifest_tag)

	# Recheck the current RVPS value supplied by KBS for every resource
	# request. This invalidates already-issued tokens immediately when the
	# single per-environment authorization is replaced, expired, or tombstoned.
	authorization := data.codewire_cpv_init_data_authorization
	is_object(authorization)
	authorization.schema_version == 1
	authorization.state == "authorized"
	authorization.environment_id == claims.codewire_workspace_storage_key_id
	authorization.storage_manifest_tag == claims.codewire_workspace_storage_manifest_tag
	authorization.init_data_sha256 == evidence.init_data
}

resource_request if {
	data.plugin == "resource"
	count(data.query) == 0
}

# The recovery key is authorized only at the path named by the measured
# environment UUID.
allow if {
	resource_request
	claims := measured_cpv_claims
	data["resource-path"] == [
		"default",
		"codewire-workspace-luks",
		claims.codewire_workspace_storage_key_id,
	]
}

# The content-addressed manifest is authorized only at the digest measured in
# the same init-data as the recovery-key UUID.
allow if {
	resource_request
	claims := measured_cpv_claims
	data["resource-path"] == [
		"default",
		"codewire-storage-manifests",
		claims.codewire_workspace_storage_manifest_tag,
	]
}

# Preserve the two path-exact resources used by the current Codewire runtime.
# They remain subject to the same affirming policy identity and measured CPV
# claims; they do not broaden the protected key or manifest namespaces.
allow if {
	resource_request
	measured_cpv_claims
	data["resource-path"] == ["default", "containers", "auth"]
}

allow if {
	resource_request
	measured_cpv_claims
	data["resource-path"] == ["default", "codewire", "runtime-test-resource"]
}
