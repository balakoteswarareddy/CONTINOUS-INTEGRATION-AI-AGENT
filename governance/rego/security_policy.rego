package ci_agent.security_policy

import rego.v1

# Security policy family (CI-Agent Production Architecture Report, Section 6 — Security).
#
# Input shape mirrors PolicySpec (src/ci_agent/core/models/policy_spec.py):
#   input.policy.security_policy := {
#     severity_thresholds: {critical: int, high: int, medium: int, low: int},
#     require_secret_scan: bool,
#     require_sca:         bool,
#   }
# Runtime facts:
#   input.findings                 := [{severity, scanner, rule_id, ...}, ...]
#   input.runtime.scans_executed   := ["secret_scan", "sca", "sast", ...]

default decision := "fail"

decision := "pass" if {
	count(exceeded_severities) == 0
	count(missing_scans) == 0
}

decision := "fail" if {
	count(exceeded_severities) > 0
}

decision := "fail" if {
	count(missing_scans) > 0
}

reasons := array.concat(severity_reasons, scan_reasons)

security_policy := object.get(object.get(input, "policy", {}), "security_policy", {})

thresholds := object.get(security_policy, "severity_thresholds", {})

findings_with_severity(sev) := [f |
	some f in object.get(input, "findings", [])
	object.get(f, "severity", "") == sev
]

exceeded_severities contains sev if {
	some sev, limit in thresholds
	count(findings_with_severity(sev)) > limit
}

severity_reasons := [msg |
	some sev in exceeded_severities
	msg := sprintf(
		"severity %q: %d findings exceed threshold %d",
		[sev, count(findings_with_severity(sev)), thresholds[sev]],
	)
]

required_scans contains "secret_scan" if {
	object.get(security_policy, "require_secret_scan", false)
}

required_scans contains "sca" if {
	object.get(security_policy, "require_sca", false)
}

scans_executed := object.get(object.get(input, "runtime", {}), "scans_executed", [])

missing_scans contains scan if {
	some scan in required_scans
	not scan in scans_executed
}

scan_reasons := [msg |
	some scan in missing_scans
	msg := sprintf("required scan %q has not been executed", [scan])
]
