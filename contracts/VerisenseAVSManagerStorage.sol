// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IVerisenseAVSManager} from "./interfaces/IVerisenseAVSManager.sol";
/**
 * @title UniFiAVSManagerStorage
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */

abstract contract VerisenseAVSManagerStorage is IVerisenseAVSManager {
    struct UniFiAVSStorage {
        mapping(bytes32 blsPubKeyHash => ValidatorData validatorData) validators;
        mapping(uint256 validatorIndex => bytes32 blsPubKeyHash) validatorIndexes;
        mapping(address operator => OperatorData operatorData) operators;
        uint64 deregistrationDelay;
        EnumerableSet.AddressSet allowlistedRestakingStrategies;
    }

    /**
     * @dev Storage slot location for UniFiAVSManager
     * @custom:storage-location erc7201:UniFiAVSManager.storage
     */
    bytes32 private constant _STORAGE_LOCATION = 0xfee41a6d2b86b757dd00cd2166d8727686a349977cbc2b6b6a2ca1c3e7215000;

    function _getUniFiAVSManagerStorage() internal pure returns (UniFiAVSStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _STORAGE_LOCATION
        }
    }
}
