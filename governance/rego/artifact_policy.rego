package ci_agent.artifact_policy

import rego.v1

# Artifact policy family (CI-Agent Production Architecture Report, Section 6 — Artifact).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.artifact_policy := {
#     require_sbom:      bool,
#     sbom_format:       "spdx" | "cyclonedx",
#     require_signing:   bool,
#     registry_allowlist:[registry, ...],
#   }
# Runtime facts:
#   input.runtime.artifacts := [{digest, registry, has_sbom, has_signature,
#                                sbom_format}, ...]
# No artifacts under evaluation -> pass (nothing is being published).

default decision := "fail"

decision := "pass" if {
	count(failures) == 0
}

decision := "fail" if {
	count(failures) > 0
}

reasons := failures

artifact_policy := object.get(object.get(input, "policy", {}), "artifact_policy", {})

artifacts := object.get(object.get(input, "runtime", {}), "artifacts", [])

failures contains msg if {
	some artifact in artifacts
	registry := object.get(artifact, "registry", "<missing>")
	not registry in object.get(artifact_policy, "registry_allowlist", [])
	msg := sprintf("artifact registry %q is not in the allowlist", [registry])
}

failures contains msg if {
	some artifact in artifacts
	object.get(artifact_policy, "require_sbom", false)
	not object.get(artifact, "has_sbom", false)
	msg := sprintf(
		"artifact %q is missing an SBOM (format %q required)",
		[object.get(artifact, "digest", "<missing>"), object.get(artifact_policy, "sbom_format", "spdx")],
	)
}

failures contains msg if {
	some artifact in artifacts
	object.get(artifact_policy, "require_signing", false)
	not object.get(artifact, "has_signature", false)
	msg := sprintf("artifact %q is not signed", [object.get(artifact, "digest", "<missing>")])
}

# Batch 7: an SBOM that EXISTS but is not in the governed format is a
# mismatch — recordable evidence of the WRONG kind of transparency. Fires
# only when has_sbom is true (a missing SBOM already fails above).
failures contains msg if {
	some artifact in artifacts
	object.get(artifact_policy, "require_sbom", false)
	object.get(artifact, "has_sbom", false)
	fmt := object.get(artifact_policy, "sbom_format", "spdx")
	artifact_format := object.get(artifact, "sbom_format", "")
	artifact_format != ""
	artifact_format != fmt
	msg := sprintf(
		"artifact %q SBOM format %q does not match governed format %q",
		[object.get(artifact, "digest", "<missing>"), artifact_format, fmt],
	)
}
