package ci_agent.identity_policy

import rego.v1

# Identity policy family (CI-Agent Production Architecture Report, Section 6 — Identity).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.identity_policy := {
#     allowed_repositories: [glob, ...],   # e.g. "org/*"
#     allowed_branches:     [glob, ...],   # e.g. "release/*"
#     allowed_identities:   [glob, ...],
#   }
# Runtime facts:
#   input.runtime.repository — always enforced (deny-by-default).
#   input.runtime.branch     — enforced when present.
#   input.runtime.identity   — enforced when present; identity binding arrives
#                              with the runner adapters (later batch), see NOTES.md.

default decision := "fail"

decision := "pass" if {
	count(failures) == 0
}

decision := "fail" if {
	count(failures) > 0
}

reasons := failures

failures contains msg if {
	not repo_allowed
	msg := sprintf(
		"repository %q is not allowed by identity policy",
		[object.get(object.get(input, "runtime", {}), "repository", "<missing>")],
	)
}

failures contains msg if {
	branch := object.get(object.get(input, "runtime", {}), "branch", null)
	branch != null
	branch != ""
	not branch_allowed(branch)
	msg := sprintf("branch %q is not allowed by identity policy", [branch])
}

failures contains msg if {
	identity := object.get(object.get(input, "runtime", {}), "identity", null)
	identity != null
	identity != ""
	not identity_allowed(identity)
	msg := sprintf("identity %q is not allowed by identity policy", [identity])
}

repo_allowed if {
	some pattern in object.get(policy, "allowed_repositories", [])
	glob.match(pattern, [], object.get(runtime, "repository", ""))
}

branch_allowed(branch) if {
	some pattern in object.get(policy, "allowed_branches", [])
	glob.match(pattern, [], branch)
}

identity_allowed(identity) if {
	some pattern in object.get(policy, "allowed_identities", [])
	glob.match(pattern, [], identity)
}

policy := object.get(object.get(input, "policy", {}), "identity_policy", {})

runtime := object.get(input, "runtime", {})
