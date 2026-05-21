package protocolgate

deny contains finding if {
  contract := input.contracts[i]
  object.get(contract, "upgradeable", false)
  admin := admin_ref(contract)
  not timelocked_governance_controller[admin]
  finding := {
    "rule_id": "CG001",
    "severity": "critical",
    "message": sprintf("%s is upgradeable but proxy/admin control is not a 24h+ timelocked governance controller", [contract.name]),
    "path": sprintf("contracts[%d].proxy.admin", [i]),
    "recommendation": "Set proxy.admin to a timelock whose proposer/executor is a declared multisig or governor."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  object.get(contract, "upgradeable", false)
  admin := admin_ref(contract)
  is_eoa(admin)
  finding := {
    "rule_id": "CG002",
    "severity": "critical",
    "message": sprintf("%s uses an EOA as upgrade admin", [contract.name]),
    "path": sprintf("contracts[%d].proxy.admin", [i]),
    "recommendation": "Move upgrade authority to a timelock controlled by a declared multisig or governor."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  fn := object.get(contract, "functions", [])[j]
  object.get(fn, "admin_only", false)
  not timelocked_governance_controller[object.get(fn, "timelock", "")]
  not timelocked_governance_controller[object.get(object.get(contract, "roles", {}), "admin", "")]
  finding := {
    "rule_id": "CG003",
    "severity": "high",
    "message": sprintf("%s.%s is admin-only without a 24h+ timelock", [contract.name, fn.name]),
    "path": sprintf("contracts[%d].functions[%d].timelock", [i, j]),
    "recommendation": "Route privileged calls through the protocol timelock."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  object.get(contract, "upgradeable", false)
  safety := object.get(contract, "upgrade_safety", {})
  object.get(safety, "storage_layout_check", false) == false
  finding := {
    "rule_id": "CG013",
    "severity": "high",
    "message": sprintf("%s does not prove storage layout upgrade checks are enabled", [contract.name]),
    "path": sprintf("contracts[%d].upgrade_safety.storage_layout_check", [i]),
    "recommendation": "Enable storage layout diff checks in CI before upgrade execution."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  ref := object.get(object.get(contract, "proxy", {}), "admin", "")
  undefined_actor(ref)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("contract %s references undefined security actor: %s", [contract.name, ref]),
    "path": sprintf("contracts[%d].proxy.admin", [i]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  roles := object.get(contract, "roles", {})
  some role
  ref := roles[role]
  undefined_actor(ref)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("contract %s role %s references undefined security actor: %s", [contract.name, role, ref]),
    "path": sprintf("contracts[%d].roles.%s", [i, role]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  fn := object.get(contract, "functions", [])[j]
  ref := object.get(fn, "timelock", "")
  undefined_actor(ref)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("%s.%s references undefined security actor: %s", [contract.name, fn.name, ref]),
    "path": sprintf("contracts[%d].functions[%d].timelock", [i, j]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}

deny contains finding if {
  timelock := input.timelocks[i]
  field := ["admin", "proposer", "executor", "controller"][_]
  ref := object.get(timelock, field, "")
  undefined_actor(ref)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("timelock %s references undefined security actor: %s", [timelock.name, ref]),
    "path": sprintf("timelocks[%d].%s", [i, field]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}

deny contains finding if {
  guardian := input.guardians[i]
  ref := object.get(guardian, "multisig", "")
  undefined_actor(ref)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("guardian %s references undefined security actor: %s", [guardian.name, ref]),
    "path": sprintf("guardians[%d].multisig", [i]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}

deny contains finding if {
  deployer := object.get(object.get(input, "deployment", {}), "allowed_deployers", [])[i]
  undefined_actor(deployer)
  finding := {
    "rule_id": "CG026",
    "severity": "high",
    "message": sprintf("deployment references undefined security actor: %s", [deployer]),
    "path": sprintf("deployment.allowed_deployers[%d]", [i]),
    "recommendation": "Define the actor in multisigs, governors, timelocks, or guardians, or use an explicit address."
  }
}
