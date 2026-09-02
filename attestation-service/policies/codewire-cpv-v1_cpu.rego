package policy

import rego.v1

# Codewire confidential persistent volumes use this policy as
# `codewire-cpv-v1_cpu`. The KBS selects the `codewire-cpv-v1` policy family;
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

executables := 3 if {
	bound_init_data
	measurements := query_reference_value("snp_launch_measurement")
	is_array(measurements)
	input.snp.measurement in measurements
}

hardware := 2 if {
	bound_init_data
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
	bound_init_data
	input.snp.policy_debug_allowed == false
	input.snp.policy_migrate_ma == false
	input.snp.platform_smt_enabled == query_reference_value("snp_smt_enabled")
	input.snp.platform_tsme_enabled == query_reference_value("snp_tsme_enabled")
	input.snp.policy_abi_major == query_reference_value("snp_guest_abi_major")
	input.snp.policy_abi_minor == query_reference_value("snp_guest_abi_minor")
	input.snp.policy_single_socket == query_reference_value("snp_single_socket")
	input.snp.policy_smt_allowed == query_reference_value("snp_smt_allowed")
}
