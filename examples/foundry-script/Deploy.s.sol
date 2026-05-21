// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
        uint256 expectedChainId = vm.envUint("CHAIN_ID");
        require(block.chainid == expectedChainId, "CHAIN_ID_MISMATCH");

        address deployer = vm.addr(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        require(deployer != address(0), "DEPLOYER_NOT_SET");

        vm.startBroadcast();
        // Deploy protocol contracts here after ProtocolGate passes in CI:
        // uv run protocolgate validate protocolgate.yaml
        vm.stopBroadcast();
    }
}
