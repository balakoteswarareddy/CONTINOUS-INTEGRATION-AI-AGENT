package ci_agent.build_policy

import rego.v1

# Build policy family (CI-Agent Production Architecture Report, Section 6 — Build).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.build_policy := {
#     allowed_base_images:    [image, ...],
#     allowed_egress_domains: [domain, ...],
#     max_timeout_seconds:    int,
#   }
# Runtime facts:
#   input.runtime.base_images          := [image, ...]
#   input.runtime.egress_domains       := [domain, ...]
#   input.runtime.step_timeout_seconds := int

default decision := "fail"

decision := "pass" if {
	count(failures) == 0
}

decision := "fail" if {
	count(failures) > 0
}

reasons := failures

build_policy := object.get(object.get(input, "policy", {}), "build_policy", {})

runtime := object.get(input, "runtime", {})

failures contains msg if {
	some image in object.get(runtime, "base_images", [])
	not image in object.get(build_policy, "allowed_base_images", [])
	msg := sprintf("base image %q is not allowlisted", [image])
}

failures contains msg if {
	some domain in object.get(runtime, "egress_domains", [])
	not domain in object.get(build_policy, "allowed_egress_domains", [])
	msg := sprintf("egress domain %q is not allowlisted", [domain])
}

failures contains msg if {
	timeout := object.get(runtime, "step_timeout_seconds", 0)
	limit := object.get(build_policy, "max_timeout_seconds", 0)
	timeout > limit
	msg := sprintf("step timeout %ds exceeds policy maximum %ds", [timeout, limit])
}
