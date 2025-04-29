// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IVerisenseAVSManager} from "./interfaces/IVerisenseAVSManager.sol";
/**
 * @title VerisenseAVSManagerStorage
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */

abstract contract VerisenseAVSManagerStorage is IVerisenseAVSManager {
    struct VerisenseAVSStorage {
        mapping(address operator => OperatorData operatorData) operators;
        EnumerableSet.AddressSet operatorAddresses;
        uint64 deregistrationDelay;
        uint256 stakeFloor;
        uint256 latestRewardedEra;
        EnumerableSet.AddressSet allowlistedRestakingStrategies;
    }
    bytes32 private constant _STORAGE_LOCATION = 0xaf993094c8eaa0abdffcc638bc8d87f9c9a50f945db9b99ab0b6681eab4f4f00;

    function _getVerisenseAVSManagerStorage() internal pure returns (VerisenseAVSStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := _STORAGE_LOCATION
        }
    }

}
