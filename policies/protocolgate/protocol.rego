package protocolgate

deny contains finding if {
  contract := input.contracts[i]
  fn := object.get(contract, "functions", [])[j]
  is_redemption(fn)
  missing := [control | control := ["cooldown", "circuit_breaker", "pause"][_]; not function_has_control(fn, control)]
  count(missing) > 0
  finding := {
    "rule_id": "CG004",
    "severity": "high",
    "message": sprintf("%s.%s lacks redemption controls: %v", [contract.name, fn.name, missing]),
    "path": sprintf("contracts[%d].functions[%d].controls", [i, j]),
    "recommendation": "Gate redemption with cooldown, circuit breaker, and emergency pause controls."
  }
}

deny contains finding if {
  bridge := input.bridges[i]
  not object.get(object.get(bridge, "rate_limits", {}), "per_block", false)
  finding := {
    "rule_id": "CG006",
    "severity": "high",
    "message": sprintf("bridge %s does not declare a per-block rate limit", [bridge.name]),
    "path": sprintf("bridges[%d].rate_limits.per_block", [i]),
    "recommendation": "Add a per-block bridge rate limit and enforce it in the bridge contract."
  }
}

deny contains finding if {
  contract := input.contracts[i]
  lower(object.get(contract, "type", "")) == "bridge"
  not object.get(object.get(contract, "rate_limits", {}), "per_block", false)
  finding := {
    "rule_id": "CG006",
    "severity": "high",
    "message": sprintf("bridge %s does not declare a per-block rate limit", [contract.name]),
    "path": sprintf("contracts[%d].rate_limits.per_block", [i]),
    "recommendation": "Add a per-block bridge rate limit and enforce it in the bridge contract."
  }
}

deny contains finding if {
  oracle := input.oracles[i]
  object.get(oracle, "max_staleness_seconds", 0) > max_oracle_staleness
  finding := {
    "rule_id": "CG007",
    "severity": "medium",
    "message": sprintf("oracle %s has unsafe staleness window", [oracle.name]),
    "path": sprintf("oracles[%d].max_staleness_seconds", [i]),
    "recommendation": "Set max_staleness_seconds to 3600 or lower for production feeds."
  }
}

deny contains finding if {
  oracle := input.oracles[i]
  object.get(oracle, "failure_mode", "") != "fail_closed"
  finding := {
    "rule_id": "CG008",
    "severity": "medium",
    "message": sprintf("oracle %s does not fail closed", [oracle.name]),
    "path": sprintf("oracles[%d].failure_mode", [i]),
    "recommendation": "Set failure_mode: fail_closed and halt dependent operations when the feed is invalid."
  }
}

deny contains finding if {
  splits := object.get(object.get(input, "treasury", {}), "splits", [])
  count(splits) > 0
  total_bps := sum([object.get(split, "bps", 0) | split := splits[_]])
  total_bps != 10000
  finding := {
    "rule_id": "CG009",
    "severity": "critical",
    "message": sprintf("treasury splits sum to %d bps, not 10000 bps", [total_bps]),
    "path": "treasury.splits",
    "recommendation": "Make treasury allocation basis points sum exactly to 10000."
  }
}

deny contains finding if {
  split := object.get(object.get(input, "treasury", {}), "splits", [])[i]
  object.get(split, "bps", 0) < 0
  finding := {
    "rule_id": "CG009",
    "severity": "critical",
    "message": sprintf("treasury split %d has negative bps=%d", [i, split.bps]),
    "path": sprintf("treasury.splits[%d].bps", [i]),
    "recommendation": "Treasury split basis points must be non-negative and sum exactly to 10000."
  }
}

deny contains finding if {
  split := object.get(object.get(input, "treasury", {}), "splits", [])[i]
  recipient := object.get(split, "recipient", "")
  recipient == ""
  finding := {
    "rule_id": "CG009",
    "severity": "critical",
    "message": sprintf("treasury split %d has an invalid recipient", [i]),
    "path": sprintf("treasury.splits[%d].recipient", [i]),
    "recommendation": "Set every treasury split recipient to an explicit non-zero destination."
  }
}

deny contains finding if {
  split := object.get(object.get(input, "treasury", {}), "splits", [])[i]
  is_zero_address(object.get(split, "recipient", ""))
  finding := {
    "rule_id": "CG009",
    "severity": "critical",
    "message": sprintf("treasury split %d has an invalid recipient", [i]),
    "path": sprintf("treasury.splits[%d].recipient", [i]),
    "recommendation": "Set every treasury split recipient to an explicit non-zero destination."
  }
}

deny contains finding if {
  multisig := input.multisigs[i]
  signers := object.get(multisig, "signers", [])
  count(signers) == 0
  finding := {
    "rule_id": "CG010",
    "severity": "critical",
    "message": sprintf("multisig %s has no signers", [multisig.name]),
    "path": sprintf("multisigs[%d].signers", [i]),
    "recommendation": "Define the signer set and set a threshold of at least 2."
  }
}

deny contains finding if {
  multisig := input.multisigs[i]
  signers := object.get(multisig, "signers", [])
  count(signers) > 0
  threshold := object.get(multisig, "threshold", 0)
  threshold < 2
  finding := {
    "rule_id": "CG010",
    "severity": "critical",
    "message": sprintf("multisig %s threshold %d/%d is a paper multisig", [multisig.name, threshold, count(signers)]),
    "path": sprintf("multisigs[%d].threshold", [i]),
    "recommendation": "Set multisig threshold to at least 2, ideally 3/5 or 5/9."
  }
}

deny contains finding if {
  multisig := input.multisigs[i]
  signers := object.get(multisig, "signers", [])
  count(signers) > 0
  threshold := object.get(multisig, "threshold", 0)
  threshold > count(signers)
  finding := {
    "rule_id": "CG010",
    "severity": "critical",
    "message": sprintf("multisig %s threshold %d/%d can never execute", [multisig.name, threshold, count(signers)]),
    "path": sprintf("multisigs[%d].threshold", [i]),
    "recommendation": "Set threshold to a value no greater than the signer count."
  }
}

deny contains finding if {
  multisig := input.multisigs[i]
  signers := object.get(multisig, "signers", [])
  count(signers) > 0
  threshold := object.get(multisig, "threshold", 0)
  threshold >= 2
  threshold <= count(signers)
  threshold * 2 < count(signers)
  finding := {
    "rule_id": "CG010",
    "severity": "high",
    "message": sprintf("multisig %s threshold %d/%d is below the production floor", [multisig.name, threshold, count(signers)]),
    "path": sprintf("multisigs[%d].threshold", [i]),
    "recommendation": "Use at least 2 signers and no less than half of the signer set."
  }
}
