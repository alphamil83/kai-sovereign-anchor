// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../contracts/KAICharterRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        KAICharterRegistry registry = new KAICharterRegistry();

        console.log("KAICharterRegistry deployed at:", address(registry));

        vm.stopBroadcast();
    }
}
