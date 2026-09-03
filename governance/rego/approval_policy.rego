package ci_agent.approval_policy

import rego.v1

# Approval policy family (CI-Agent Production Architecture Report, Section 6 — Approval).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.approval_policy := {
#     require_human_approval_for: [risk_tier, ...],
#     approver_groups:            [group, ...],
#   }
# Runtime facts:
#   input.runtime.risk_tier  := "low" | "medium" | "high" | "regulated"
#   input.runtime.approvals  := [{approver_group, status}, ...]
#
# Fail-closed (Batch 1 NOTES, Section 7 trust boundaries): if approval is
# required but NO approver groups are configured, this gate can never pass.

default decision := "fail"

decision := "pass" if {
	not approval_required
}

decision := "pass" if {
	approval_required
	has_approver_groups
	has_valid_approval
}

decision := "fail" if {
	approval_required
	not has_approver_groups
}

decision := "fail" if {
	approval_required
	has_approver_groups
	not has_valid_approval
}

reasons contains "human approval is required but no approver groups are configured (fail closed)" if {
	approval_required
	not has_approver_groups
}

reasons contains msg if {
	approval_required
	has_approver_groups
	not has_valid_approval
	msg := sprintf(
		"no approved record from any configured approver group (risk tier %q)",
		[object.get(runtime, "risk_tier", "")],
	)
}

policy := object.get(object.get(input, "policy", {}), "approval_policy", {})

runtime := object.get(input, "runtime", {})

approval_required if {
	object.get(runtime, "risk_tier", "") in object.get(policy, "require_human_approval_for", [])
}

has_approver_groups if {
	count(object.get(policy, "approver_groups", [])) > 0
}

has_valid_approval if {
	some approval in object.get(runtime, "approvals", [])
	object.get(approval, "status", "") == "approved"
	object.get(approval, "approver_group", "") in object.get(policy, "approver_groups", [])
}
