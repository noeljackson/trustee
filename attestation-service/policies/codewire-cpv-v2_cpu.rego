package policy

import rego.v1

# Codewire confidential persistent volumes use this policy as
# `codewire-cpv-v2_cpu`. The KBS selects the `codewire-cpv-v2` policy family;
# the Attestation Service appends the evidence class suffix.

# Conservative defaults make the resulting EAR appraisal contraindicated when
# the evidence is not SNP, init-data is absent, or any approved TCB reference
# value does not match.
default executables := 33
default hardware := 97
default configuration := 36
default file_system := 0
default instance_identity := 0
default runtime_opaque := 0
default storage_opaque := 0
default sourced_data := 0

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": file_system,
	"instance-identity": instance_identity,
	"runtime-opaque": runtime_opaque,
	"storage-opaque": storage_opaque,
	"sourced-data": sourced_data,
}

# The SNP verifier adds `init_data` only after the supplied init-data digest
# matches HOST_DATA. Requiring both the verified digest and parsed claims makes
# omission fail closed before resource authorization is considered.
bound_init_data if {
	input.snp
	regex.match("^[0-9a-f]{64}$", input.init_data)
	is_object(input.init_data_claims)
}

environment_id_pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
storage_manifest_tag_pattern := "^sha256-[0-9a-f]{64}$"

# The launcher controls HOST_DATA and the init-data bytes together. Trust them
# only when Codewire's authenticated KBS administrator has preauthorized the
# complete raw init-data digest in the canonical per-environment RVPS record.
# The single record is atomically replaceable and a non-authorized state is a
# tombstone, so policy/workload replacement and revocation fail closed.
owner_authorized_init_data if {
	bound_init_data
	claims := input.init_data_claims
	regex.match(environment_id_pattern, claims.codewire_workspace_storage_key_id)
	regex.match(storage_manifest_tag_pattern, claims.codewire_workspace_storage_manifest_tag)

	reference_id := sprintf("codewire_cpv_init_data/%s", [claims.codewire_workspace_storage_key_id])
	authorization := query_reference_value(reference_id)
	is_object(authorization)
	authorization.schema_version == 1
	authorization.state == "authorized"
	authorization.environment_id == claims.codewire_workspace_storage_key_id
	authorization.storage_manifest_tag == claims.codewire_workspace_storage_manifest_tag
	authorization.init_data_sha256 == input.init_data
}

executables := 3 if {
	owner_authorized_init_data
	measurements := query_reference_value("snp_launch_measurement")
	is_array(measurements)
	input.snp.measurement in measurements
}

hardware := 2 if {
	owner_authorized_init_data
	bootloaders := query_reference_value("snp_bootloader")
	microcodes := query_reference_value("snp_microcode")
	snp_svns := query_reference_value("snp_snp_svn")
	tee_svns := query_reference_value("snp_tee_svn")
	is_array(bootloaders)
	is_array(microcodes)
	is_array(snp_svns)
	is_array(tee_svns)
	input.snp.reported_tcb_bootloader in bootloaders
	input.snp.reported_tcb_microcode in microcodes
	input.snp.reported_tcb_snp in snp_svns
	input.snp.reported_tcb_tee in tee_svns
}

configuration := 2 if {
	owner_authorized_init_data
	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
	input.snp.platform_smt_enabled == query_reference_value("snp_smt_enabled")
	input.snp.platform_tsme_enabled == query_reference_value("snp_tsme_enabled")
	input.snp.policy_abi_major == query_reference_value("snp_guest_abi_major")
	input.snp.policy_abi_minor == query_reference_value("snp_guest_abi_minor")
	input.snp.policy_single_socket == query_reference_value("snp_single_socket")
	input.snp.policy_smt_allowed == query_reference_value("snp_smt_allowed")
}
