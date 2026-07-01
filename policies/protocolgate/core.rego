package protocolgate

# Experimental OPA subset. The built-in Python engine is canonical until the
# Rego pack reaches parity.

min_admin_delay := 86400
max_oracle_staleness := 3600
zero_address := "0x0000000000000000000000000000000000000000"

multisig_name contains name if {
  name := input.multisigs[_].name
}

governor_name contains name if {
  name := input.governors[_].name
}

valid_actor contains name if {
  name := input.multisigs[_].name
}

valid_actor contains name if {
  name := input.governors[_].name
}

valid_actor contains name if {
  name := input.timelocks[_].name
}

valid_actor contains name if {
  name := input.guardians[_].name
}

timelocked_governance_controller contains name if {
  timelock := input.timelocks[_]
  name := timelock.name
  object.get(timelock, "delay_seconds", 0) >= min_admin_delay
  controller := [object.get(timelock, "admin", ""), object.get(timelock, "proposer", ""), object.get(timelock, "executor", ""), object.get(timelock, "controller", "")][_]
  multisig_name[controller]
}

timelocked_governance_controller contains name if {
  timelock := input.timelocks[_]
  name := timelock.name
  object.get(timelock, "delay_seconds", 0) >= min_admin_delay
  controller := [object.get(timelock, "admin", ""), object.get(timelock, "proposer", ""), object.get(timelock, "executor", ""), object.get(timelock, "controller", "")][_]
  governor_name[controller]
}

admin_ref(contract) := admin if {
  admin := object.get(object.get(contract, "proxy", {}), "admin", "")
  admin != ""
}

admin_ref(contract) := admin if {
  object.get(object.get(contract, "proxy", {}), "admin", "") == ""
  admin := object.get(object.get(contract, "roles", {}), "admin", "")
}

is_eoa(ref) if {
  is_string(ref)
  startswith(ref, "0x")
  count(ref) == 42
}

is_zero_address(ref) if {
  is_string(ref)
  lower(ref) == zero_address
}

is_named_actor_ref(ref) if {
  is_string(ref)
  ref != ""
  not is_eoa(ref)
}

undefined_actor(ref) if {
  is_named_actor_ref(ref)
  not valid_actor[ref]
}

function_has_control(fn, control) if {
  fn.controls[_] == control
}

function_has_control(fn, "cooldown") if {
  object.get(fn, "cooldown_seconds", 0) > 0
}

function_has_control(fn, "circuit_breaker") if {
  object.get(fn, "circuit_breaker", false)
}

function_has_control(fn, "pause") if {
  object.get(fn, "pausable", false)
}

function_has_control(fn, "nonReentrant") if {
  object.get(fn, "non_reentrant", false)
}

is_redemption(fn) if {
  object.get(fn, "category", "") == "redemption"
}

is_redemption(fn) if {
  contains(lower(object.get(fn, "name", "")), "redeem")
}
