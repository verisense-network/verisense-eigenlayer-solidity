// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { EnumerableMap } from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import { ISignatureUtils } from "eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { IStrategy } from "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import { IAVSDirectory } from "eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IDelegationManager } from "eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { IEigenPodManager } from "eigenlayer-contracts/src/contracts/interfaces/IEigenPodManager.sol";
import { IEigenPod } from "eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import {IVerisenseAVSManager} from "./interfaces/IVerisenseAVSManager.sol";
import {VerisenseAVSManagerStorage} from "./VerisenseAVSManagerStorage.sol";
import { IRewardsCoordinator } from "eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VerisenseAVSManager is VerisenseAVSManagerStorage, UUPSUpgradeable, OwnableUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;
    using SafeERC20 for IERC20;
    IEigenPodManager public EIGEN_POD_MANAGER;

    IDelegationManager public EIGEN_DELEGATION_MANAGER;

    IRewardsCoordinator public EIGEN_REWARDS_COORDINATOR;

    IAVSDirectory public AVS_DIRECTORY;

    function _getAvsOperatorStatus(address operator)
        internal
        view
        returns (IAVSDirectory.OperatorAVSRegistrationStatus)
    {
        (bool success, bytes memory data) = address(AVS_DIRECTORY).staticcall(
            abi.encodeWithSelector(bytes4(keccak256("avsOperatorStatus(address,address)")), address(this), operator)
        );
        if (!success) {
            revert AVSOperatorStatusCallFailed();
        }
        return abi.decode(data, (IAVSDirectory.OperatorAVSRegistrationStatus));
    }

    modifier registeredOperator(address operator) {
        if (_getAvsOperatorStatus(operator) == IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED) {
            revert OperatorNotRegistered();
        }
        _;
    }


    function initialize(
        address eigenPodManagerAddress,
        address eigenDelegationManagerAddress,
        address avsDirectoryAddress,
        address rewardsCoordinatorAddress,
        uint64 initialDeregistrationDelay) public initializer {
        if (eigenPodManagerAddress == address(0)) {
            revert InvalidEigenPodManagerAddress();
        }
        if (eigenDelegationManagerAddress == address(0)) {
            revert InvalidEigenDelegationManagerAddress();
        }
        if (avsDirectoryAddress == address(0)) {
            revert InvalidAVSDirectoryAddress();
        }
        if (rewardsCoordinatorAddress == address(0)) {
            revert InvalidRewardsCoordinatorAddress();
        }
        EIGEN_POD_MANAGER = IEigenPodManager(eigenPodManagerAddress);
        EIGEN_DELEGATION_MANAGER = IDelegationManager(eigenDelegationManagerAddress);
        AVS_DIRECTORY = IAVSDirectory(avsDirectoryAddress);
        EIGEN_REWARDS_COORDINATOR = IRewardsCoordinator(rewardsCoordinatorAddress);
        _setDeregistrationDelay(initialDeregistrationDelay);
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature, bytes32 substrate_pubkey)
        external
    {
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);
        _getVerisenseAVSManagerStorage().operators[msg.sender].substrate_pubkey = substrate_pubkey;
        _getVerisenseAVSManagerStorage().operatorAddresses.add(msg.sender);
        emit OperatorRegistered(msg.sender);
    }

    function startDeregisterOperator() external registeredOperator(msg.sender) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.startDeregisterOperatorBlock != 0) {
            revert DeregistrationAlreadyStarted();
        }

        operator.startDeregisterOperatorBlock = uint64(block.number);

        emit OperatorDeregisterStarted(msg.sender);
    }

    function finishDeregisterOperator() external registeredOperator(msg.sender) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.startDeregisterOperatorBlock == 0) {
            revert DeregistrationNotStarted();
        }

        if (block.number < operator.startDeregisterOperatorBlock + $.deregistrationDelay) {
            revert DeregistrationDelayNotElapsed();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        delete $.operators[msg.sender];
        $.operatorAddresses.remove(msg.sender);

        emit OperatorDeregistered(msg.sender);
    }

    function setDeregistrationDelay(uint64 newDelay) external onlyOwner {
        _setDeregistrationDelay(newDelay);
    }

    function updateAVSMetadataURI(string memory _metadataURI) external onlyOwner {
        AVS_DIRECTORY.updateAVSMetadataURI(_metadataURI);
    }

    function setAllowlistRestakingStrategy(address strategy, bool allowed) external onlyOwner {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        bool success;
        if (allowed) {
            success = $.allowlistedRestakingStrategies.add(strategy);
        } else {
            success = $.allowlistedRestakingStrategies.remove(strategy);
        }
        if (success) {
            emit RestakingStrategyAllowlistUpdated(strategy, allowed);
        } else {
            revert RestakingStrategyAllowlistUpdateFailed();
        }
    }

    function submitOperatorRewards(IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions)
        external
        onlyOwner
    {
        uint256 submissionsLength = submissions.length;
        for (uint256 i = 0; i < submissionsLength; i++) {
            IRewardsCoordinator.OperatorDirectedRewardsSubmission calldata submission = submissions[i];
            uint256 totalRewards = 0;
            uint256 rewardsLength = submission.operatorRewards.length;
            for (uint256 j = 0; j < rewardsLength; j++) {
                totalRewards += submission.operatorRewards[j].amount;
            }
            IERC20(address(submission.token)).safeIncreaseAllowance(address(EIGEN_REWARDS_COORDINATOR), totalRewards);
        }
        EIGEN_REWARDS_COORDINATOR.createOperatorDirectedAVSRewardsSubmission(address(this), submissions);
        emit OperatorRewardsSubmitted();
    }

    function setClaimerFor(address claimer) external onlyOwner {
        EIGEN_REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    function getDeregistrationDelay() external view returns (uint64) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        return $.deregistrationDelay;
    }

    function getOperator(address operator) external view returns (OperatorDataExtended memory) {
        return _getOperator(operator);
    }

    function getOperators() external view returns (OperatorValidData[] memory) {
        uint256 operators_size = _getVerisenseAVSManagerStorage().operatorAddresses.length();
        OperatorValidData[]  memory validators = new OperatorValidData[](operators_size);
        IStrategy[] memory strategies = _getStrategies();
        for (uint256 i; i < operators_size; i++) {
            address key = _getVerisenseAVSManagerStorage().operatorAddresses.at(i);
            OperatorData memory d = _getVerisenseAVSManagerStorage().operators[key];
            OperatorValidData memory dv = OperatorValidData({
                substratePubkey : d.substrate_pubkey,
                operator : key,
                stake : _getOperatorStake(key, strategies),
                isRegistered : _getAvsOperatorStatus(key) == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED,
                restakedStrategies : sortAddresses(_getOperatorRestakedStrategies(key))
            });
            validators[i] = dv;
        }
        return validators;
    }

    function _getOperatorRestakedStrategies(address operator) internal view
                    returns (address[] memory restakedStrategies) {
        OperatorDataExtended memory operatorData = _getOperator(operator);
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();

        if (operatorData.isRegistered) {
            uint256 allowlistedCount = $.allowlistedRestakingStrategies.length();
            IStrategy[] memory strategies = new IStrategy[](allowlistedCount);
            for (uint256 i = 0; i < allowlistedCount; i++) {
                strategies[i] = IStrategy($.allowlistedRestakingStrategies.at(i));
            }

            uint256[] memory shares = EIGEN_DELEGATION_MANAGER.getOperatorShares(operator, strategies);

            uint256 restakedCount = 0;
            restakedStrategies = new address[](allowlistedCount);

            for (uint256 i = 0; i < allowlistedCount; i++) {
                if (shares[i] > 0) {
                    restakedStrategies[restakedCount++] = address(strategies[i]);
                }
            }

            // Resize the array to the actual number of restaked strategies
            assembly {
                if lt(restakedCount, allowlistedCount) { mstore(restakedStrategies, restakedCount) }
            }
        }
    }
    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (address[] memory restakedStrategies)
    {
       return _getOperatorRestakedStrategies(operator);
    }

    function _getOperatorStake(address operator, IStrategy[] memory strategies) internal view returns (uint256) {
        uint256[] memory shares = EIGEN_DELEGATION_MANAGER.getOperatorShares(operator, strategies);
        uint256 total_shares = 0;
        for (uint256 i = 0; i < shares.length; i++) {
            total_shares += shares[i];
        }
        return total_shares;
    }

    function _getStrategies() internal view returns (IStrategy[] memory) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        uint256 allowlistedCount = $.allowlistedRestakingStrategies.length();
        IStrategy[] memory strategies = new IStrategy[](allowlistedCount);
        for (uint256 i = 0; i < allowlistedCount; i++) {
            strategies[i] = IStrategy($.allowlistedRestakingStrategies.at(i));
        }
        return strategies;
    }

    function getRestakeableStrategies() external view returns (address[] memory) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        return $.allowlistedRestakingStrategies.values();
    }

    function _getOperator(address operator) internal view returns (OperatorDataExtended memory) {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        OperatorData storage operatorData = $.operators[operator];
        return OperatorDataExtended({
            startDeregisterOperatorBlock: operatorData.startDeregisterOperatorBlock,
            isRegistered: _getAvsOperatorStatus(operator) == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
        });
    }

    function _setDeregistrationDelay(uint64 newDelay) internal {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        uint64 oldDelay = $.deregistrationDelay;
        $.deregistrationDelay = newDelay;
        emit DeregistrationDelaySet(oldDelay, newDelay);
    }

    function sortAddresses(address[] memory arr) internal pure returns (address[] memory) {
        if (arr.length == 0) {
            return arr;
        }
        address[] memory sortedArr = new address[](arr.length);
        for (uint i = 0; i < arr.length; i++) {
            sortedArr[i] = arr[i];
        }
        for (uint i = 0; i < sortedArr.length - 1; i++) {
            for (uint j = 0; j < sortedArr.length - i - 1; j++) {
                if (uint160(sortedArr[j]) > uint160(sortedArr[j + 1])) {
                    (sortedArr[j], sortedArr[j + 1]) = (sortedArr[j + 1], sortedArr[j]);
                }
            }
        }
        return sortedArr;
    }

    function calculateOperatorAVSRegistrationDigestHash(
        address operator,
        address avs,
        bytes32 salt,
        uint256 expiry
    ) public view returns (bytes32) {
        bytes32 OPERATOR_AVS_REGISTRATION_TYPEHASH =
        keccak256("OperatorAVSRegistration(address operator,address avs,bytes32 salt,uint256 expiry)");
        // calculate the struct hash
        bytes32 sep = AVS_DIRECTORY.domainSeparator();
        bytes32 structHash = keccak256(abi.encode(OPERATOR_AVS_REGISTRATION_TYPEHASH, operator, avs, salt, expiry));
        // calculate the digest hash
        bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", sep, structHash));
        return digestHash;
    }

    function ecdsa_check(bytes32 message_hash, bytes memory signature ) public pure returns (address) {
        return ECDSA.recover(message_hash, signature);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }
}
