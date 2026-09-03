package ci_agent.ai_policy

import rego.v1

# AI policy family (CI-Agent Production Architecture Report, Sections 6 and 7.1).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.ai_policy := {
#     allowed_model_providers:     [provider, ...],
#     allowed_data_classification: [classification, ...],   # see data_classification.yaml
#     require_human_override:      bool,
#   }
# Runtime facts:
#   input.runtime.ai_invocation := {model_provider, data_classification, human_override}
#                                  or null/absent when no AI model is involved
#                                  (nothing is being sent -> pass).

default decision := "fail"

decision := "pass" if {
	invocation == null
}

decision := "pass" if {
	invocation != null
	provider_allowed
	classification_allowed
	not override_required
}

decision := "pass" if {
	invocation != null
	provider_allowed
	classification_allowed
	override_required
	object.get(invocation, "human_override", false) == true
}

reasons contains "no AI model providers are approved (deny-by-default)" if {
	invocation != null
	not provider_allowed
}

reasons contains msg if {
	invocation != null
	provider_allowed
	not classification_allowed
	msg := sprintf(
		"data classification %q may not be sent to AI providers",
		[object.get(invocation, "data_classification", "")],
	)
}

reasons contains "AI policy requires a human override and none is recorded" if {
	invocation != null
	provider_allowed
	classification_allowed
	override_required
	object.get(invocation, "human_override", false) != true
}

policy := object.get(object.get(input, "policy", {}), "ai_policy", {})

invocation := object.get(object.get(input, "runtime", {}), "ai_invocation", null)

override_required if {
	object.get(policy, "require_human_override", true)
}

provider_allowed if {
	object.get(invocation, "model_provider", "") in object.get(policy, "allowed_model_providers", [])
}

classification_allowed if {
	object.get(invocation, "data_classification", "") in object.get(policy, "allowed_data_classification", [])
}
