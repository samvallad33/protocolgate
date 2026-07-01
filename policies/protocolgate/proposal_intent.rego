package protocolgate

# Experimental OPA subset for Proposal Intent Gate controls. The built-in
# Python engine remains canonical for CG032-CG038.

proposal_config := object.get(input, "proposal_intent", {})

high_privilege_category contains "admin_transfer"
high_privilege_category contains "bridge_limit_change"
high_privilege_category contains "mint_cap_change"
high_privilege_category contains "oracle_change"
high_privilege_category contains "treasury_transfer"
high_privilege_category contains "upgrade"
high_privilege_category contains "withdrawal_limit_change"

default_privileged_selector contains "changeAdmin(address)"
default_privileged_selector contains "grantRole(bytes32,address)"
default_privileged_selector contains "mint(address,uint256)"
default_privileged_selector contains "pause()"
default_privileged_selector contains "revokeRole(bytes32,address)"
default_privileged_selector contains "setBridgeLimit(uint256)"
default_privileged_selector contains "setFeeBps(uint256)"
default_privileged_selector contains "setOracle(address)"
default_privileged_selector contains "setWithdrawalLimit(uint256)"
default_privileged_selector contains "unpause()"
default_privileged_selector contains "upgradeTo(address)"
default_privileged_selector contains "upgradeToAndCall(address,bytes)"

configured_privileged_selector contains selector if {
  selector := object.get(proposal_config, "privileged_selectors", [])[_]
}

allowed_selector(selector) if {
  object.get(proposal_config, "privileged_selectors", [])[_] == selector
}

allowed_selector(selector) if {
  count(object.get(proposal_config, "privileged_selectors", [])) == 0
  default_privileged_selector[selector]
}

high_privilege(proposal) if {
  category := object.get(proposal, "category", "")
  high_privilege_category[category]
}

high_privilege(proposal) if {
  selector := object.get(proposal, "selector", "")
  default_privileged_selector[selector]
}

high_privilege(proposal) if {
  selector := object.get(proposal, "selector", "")
  configured_privileged_selector[selector]
}

deny contains finding if {
  object.get(proposal_config, "require_metadata", true)
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  object.get(proposal, "intent", "") == ""
  finding := {
    "rule_id": "CG032",
    "severity": "high",
    "message": sprintf("proposal %s is missing intent", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].intent", [i]),
    "recommendation": "Require privileged proposals to include signer-readable metadata before approval."
  }
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  object.get(proposal, "expires_at", "") == ""
  finding := {
    "rule_id": "CG033",
    "severity": "critical",
    "message": sprintf("proposal %s has no expiry", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].expires_at", [i]),
    "recommendation": "Set an explicit expiry so pre-signed privileged approvals cannot live forever."
  }
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  created := time.parse_rfc3339_ns(object.get(proposal, "created_at", ""))
  expires := time.parse_rfc3339_ns(object.get(proposal, "expires_at", ""))
  max_validity := object.get(proposal_config, "max_validity_seconds", 86400)
  ((expires - created) / 1000000000) > max_validity
  finding := {
    "rule_id": "CG033",
    "severity": "critical",
    "message": sprintf("proposal %s exceeds the configured validity window", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].expires_at", [i]),
    "recommendation": sprintf("Limit privileged proposal validity to %d seconds or less.", [max_validity])
  }
}

deny contains finding if {
  object.get(proposal_config, "require_calldata_hash_match", true)
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  object.get(proposal, "reviewed_calldata_hash", "") == ""
  finding := {
    "rule_id": "CG034",
    "severity": "critical",
    "message": sprintf("proposal %s has no valid reviewed calldata hash", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].reviewed_calldata_hash", [i]),
    "recommendation": "Bind signer review to a 32-byte calldata hash before signatures are collected."
  }
}

deny contains finding if {
  object.get(proposal_config, "require_calldata_hash_match", true)
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  reviewed := object.get(proposal, "reviewed_calldata_hash", "")
  executed := object.get(proposal, "execution_calldata_hash", "")
  reviewed != ""
  lower(reviewed) != lower(executed)
  finding := {
    "rule_id": "CG034",
    "severity": "critical",
    "message": sprintf("proposal %s execution calldata does not match reviewed intent", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].execution_calldata_hash", [i]),
    "recommendation": "Require the reviewed calldata hash and execution calldata hash to match before signing."
  }
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  selector := object.get(proposal, "selector", "")
  selector != ""
  not allowed_selector(selector)
  finding := {
    "rule_id": "CG035",
    "severity": "high",
    "message": sprintf("proposal %s uses unapproved privileged selector %s", [object.get(proposal, "id", i), selector]),
    "path": sprintf("proposal_intent.proposals[%d].selector", [i]),
    "recommendation": "Allowlist selectors that can change upgrades, admins, bridges, oracles, supply, treasury, or emergency controls."
  }
}

allowed_safe_module contains name if {
  name := object.get(proposal_config, "allowed_safe_modules", [])[_]
}

declared_safe_module contains name if {
  module := object.get(proposal_config, "safe_modules", [])[_]
  object.get(module, "enabled", true)
  name := object.get(module, "name", "")
  name != ""
}

deny contains finding if {
  module := object.get(proposal_config, "safe_modules", [])[i]
  object.get(module, "enabled", true)
  name := object.get(module, "name", "")
  not allowed_safe_module[name]
  finding := {
    "rule_id": "CG036",
    "severity": "high",
    "message": sprintf("Safe module %s is not in the module allowlist", [name]),
    "path": sprintf("proposal_intent.safe_modules[%d].name", [i]),
    "recommendation": "Declare and review every Safe or Squads module that can execute transactions outside normal signer flow."
  }
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  field := ["module", "safe_module"][_]
  name := object.get(proposal, field, "")
  name != ""
  not declared_safe_module[name]
  finding := {
    "rule_id": "CG036",
    "severity": "high",
    "message": sprintf("proposal %s uses undeclared Safe/Squads module %s", [object.get(proposal, "id", i), name]),
    "path": sprintf("proposal_intent.proposals[%d].%s", [i, field]),
    "recommendation": "Declare and allowlist every Safe or Squads module used to execute privileged proposals."
  }
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  field := ["module", "safe_module"][_]
  name := object.get(proposal, field, "")
  name != ""
  declared_safe_module[name]
  not allowed_safe_module[name]
  finding := {
    "rule_id": "CG036",
    "severity": "high",
    "message": sprintf("proposal %s uses unapproved Safe/Squads module %s", [object.get(proposal, "id", i), name]),
    "path": sprintf("proposal_intent.proposals[%d].%s", [i, field]),
    "recommendation": "Declare and allowlist every Safe or Squads module used to execute privileged proposals."
  }
}

deny contains finding if {
  object.get(proposal_config, "require_simulation", true)
  proposal := object.get(proposal_config, "proposals", [])[i]
  high_privilege(proposal)
  object.get(object.get(proposal, "simulation", {}), "status", "") != "passed"
  finding := {
    "rule_id": "CG037",
    "severity": "high",
    "message": sprintf("proposal %s has no passed transaction simulation", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].simulation.status", [i]),
    "recommendation": "Simulate privileged transactions before collecting signatures."
  }
}

monitor_required_category contains category if {
  category := object.get(proposal_config, "monitor_required_for", [])[_]
}

deny contains finding if {
  proposal := object.get(proposal_config, "proposals", [])[i]
  category := object.get(proposal, "category", "")
  monitor_required_category[category]
  not object.get(object.get(proposal, "monitor", {}), "enabled", false)
  finding := {
    "rule_id": "CG038",
    "severity": "medium",
    "message": sprintf("proposal %s has no monitor coverage", [object.get(proposal, "id", i)]),
    "path": sprintf("proposal_intent.proposals[%d].monitor.enabled", [i]),
    "recommendation": "Attach monitor coverage to admin, oracle, bridge, treasury, and supply-control proposals."
  }
}
