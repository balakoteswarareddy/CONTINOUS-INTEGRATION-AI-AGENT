package ci_agent.tool_policy

import rego.v1

# Tool policy family (CI-Agent Production Architecture Report, Section 6 — Tool).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.tool_policy := {
#     approved_tool_versions: {tool_name: version},
#     approved_images:        [image, ...],
#     forbidden_tools:        [tool_name, ...],
#   }
# Runtime facts:
#   input.runtime.tools := [{name, version, container_image}, ...]
#
# Steps whose tool_name starts with "internal." are the Section 5.1
# control-flow gates (policy gate / human approval / merge decision) and are
# exempt from external-tool approval (documented in NOTES.md).

default decision := "fail"

decision := "pass" if {
	count(failures) == 0
}

decision := "fail" if {
	count(failures) > 0
}

reasons := failures

policy := object.get(object.get(input, "policy", {}), "tool_policy", {})

approved_versions := object.get(policy, "approved_tool_versions", {})

tools := [t |
	some t in object.get(object.get(input, "runtime", {}), "tools", [])
	not startswith(object.get(t, "name", ""), "internal.")
]

failures contains msg if {
	some t in tools
	approved := object.get(approved_versions, t.name, "<unapproved>")
	approved != object.get(t, "version", "<missing>")
	msg := sprintf(
		"tool %q version %q is not approved (approved: %q)",
		[t.name, object.get(t, "version", "<missing>"), approved],
	)
}

failures contains msg if {
	some t in tools
	t.name in object.get(policy, "forbidden_tools", [])
	msg := sprintf("tool %q is forbidden", [t.name])
}

failures contains msg if {
	some t in tools
	image := object.get(t, "container_image", null)
	image != null
	image != ""
	not image_approved(image)
	msg := sprintf("container image %q is not in tool policy approved_images", [image])
}

image_approved(image) if {
	some approved in object.get(policy, "approved_images", [])
	approved == image
}
