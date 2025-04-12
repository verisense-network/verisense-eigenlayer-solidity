// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
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

contract VerisenseAVSManager is VerisenseAVSManagerStorage, UUPSUpgradeable, AccessManagedUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;
    using SafeERC20 for IERC20;

    address public constant BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

    /**
     * @notice The EigenPodManager
     */
    IEigenPodManager public immutable override EIGEN_POD_MANAGER;
    /**
     * @notice The EigenDelegationManager
     */
    IDelegationManager public immutable override EIGEN_DELEGATION_MANAGER;
    /**
     * @notice The RewardsCoordinator contract
     */
    IRewardsCoordinator public immutable EIGEN_REWARDS_COORDINATOR;
    /**
     * @notice The AVSDirectory contract
     */
    IAVSDirectory public immutable override AVS_DIRECTORY;

    /**
     * @dev Modifier to check if the pod is delegated to the msg.sender
     * @param podOwner The address of the pod owner
     */
    modifier podIsDelegatedToMsgSender(address podOwner) {
        if (!EIGEN_DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert NotOperator();
        }
        if (!EIGEN_POD_MANAGER.hasPod(podOwner)) {
            revert NoEigenPod();
        }
        if (EIGEN_DELEGATION_MANAGER.delegatedTo(podOwner) != msg.sender) {
            revert NotDelegatedToOperator();
        }
        _;
    }

    /**
     * @dev Internal function to get AVS operator status via staticcall
     * @param operator The address of the operator
     */
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

    /**
     * @dev Modifier to check if the operator is registered in the AVS
     * @param operator The address of the operator
     */
    modifier registeredOperator(address operator) {
        if (_getAvsOperatorStatus(operator) == IAVSDirectory.OperatorAVSRegistrationStatus.UNREGISTERED) {
            revert OperatorNotRegistered();
        }
        _;
    }

    constructor(
        IEigenPodManager eigenPodManagerAddress,
        IDelegationManager eigenDelegationManagerAddress,
        IAVSDirectory avsDirectoryAddress,
        IRewardsCoordinator rewardsCoordinatorAddress
    ) {
        if (address(eigenPodManagerAddress) == address(0)) {
            revert InvalidEigenPodManagerAddress();
        }
        if (address(eigenDelegationManagerAddress) == address(0)) {
            revert InvalidEigenDelegationManagerAddress();
        }
        if (address(avsDirectoryAddress) == address(0)) {
            revert InvalidAVSDirectoryAddress();
        }
        if (address(rewardsCoordinatorAddress) == address(0)) {
            revert InvalidRewardsCoordinatorAddress();
        }
        EIGEN_POD_MANAGER = eigenPodManagerAddress;
        EIGEN_DELEGATION_MANAGER = eigenDelegationManagerAddress;
        AVS_DIRECTORY = IAVSDirectory(address(avsDirectoryAddress));
        EIGEN_REWARDS_COORDINATOR = IRewardsCoordinator(address(rewardsCoordinatorAddress));
        _disableInitializers();
    }

    function initialize(address accessManager, uint64 initialDeregistrationDelay) public initializer {
        __AccessManaged_init(accessManager);
        _setDeregistrationDelay(initialDeregistrationDelay);

        // Initialize BEACON_CHAIN_STRATEGY as an allowed restaking strategy
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        $.allowlistedRestakingStrategies.add(BEACON_CHAIN_STRATEGY);
    }

    // EXTERNAL FUNCTIONS

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature)
        external
        restricted
    {
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        emit OperatorRegistered(msg.sender);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerOperatorWithCommitment(
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature,
        OperatorCommitment calldata initialCommitment
    ) external restricted {
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        _getUniFiAVSManagerStorage().operators[msg.sender].commitment = initialCommitment;

        emit OperatorRegisteredWithCommitment(msg.sender, initialCommitment);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerValidators(address podOwner, bytes32[] calldata blsPubKeyHashes)
        external
        podIsDelegatedToMsgSender(podOwner)
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        bytes memory delegateKey = _getActiveCommitment($.operators[msg.sender]).delegateKey;

        if (delegateKey.length == 0) {
            revert DelegateKeyNotSet();
        }

        IEigenPod eigenPod = EIGEN_POD_MANAGER.getPod(podOwner);

        uint256 newValidatorCount = blsPubKeyHashes.length;

        for (uint256 i = 0; i < newValidatorCount; i++) {
            bytes32 blsPubKeyHash = blsPubKeyHashes[i];
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyHashToInfo(blsPubKeyHash);

            if (validatorInfo.status != IEigenPod.VALIDATOR_STATUS.ACTIVE) {
                revert ValidatorNotActive();
            }

            if ($.validators[blsPubKeyHash].index != 0) {
                revert ValidatorAlreadyRegistered();
            }

            // Store the validator record
            $.validators[blsPubKeyHash] = ValidatorData({
                eigenPod: address(eigenPod),
                index: validatorInfo.validatorIndex,
                operator: msg.sender,
                registeredUntil: type(uint64).max
            });

            // Also track the mapping from index -> BLS key
            $.validatorIndexes[validatorInfo.validatorIndex] = blsPubKeyHash;

            emit ValidatorRegistered({
                podOwner: podOwner,
                operator: msg.sender,
                delegateKey: delegateKey,
                blsPubKeyHash: blsPubKeyHash,
                validatorIndex: validatorInfo.validatorIndex
            });
        }

        OperatorData storage operator = $.operators[msg.sender];
        operator.validatorCount += uint128(newValidatorCount);
        operator.startDeregisterOperatorBlock = 0;
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function deregisterValidators(bytes32[] calldata blsPubKeyHashes) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        uint256 validatorCount = blsPubKeyHashes.length;

        for (uint256 i = 0; i < validatorCount; i++) {
            bytes32 blsPubKeyHash = blsPubKeyHashes[i];
            ValidatorData storage validator = $.validators[blsPubKeyHash];

            address operator = validator.operator;

            if (operator != msg.sender) {
                revert NotValidatorOperator();
            }

            if (validator.registeredUntil != type(uint64).max) {
                revert ValidatorAlreadyDeregistered();
            }

            // Mark the validator as deregistered
            validator.registeredUntil = uint64(block.number);

            emit ValidatorDeregistered({ operator: operator, blsPubKeyHash: blsPubKeyHash });
        }

        $.operators[msg.sender].validatorCount -= uint128(validatorCount);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function startDeregisterOperator() external registeredOperator(msg.sender) restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.validatorCount > 0) {
            revert OperatorHasValidators();
        }

        if (operator.startDeregisterOperatorBlock != 0) {
            revert DeregistrationAlreadyStarted();
        }

        operator.startDeregisterOperatorBlock = uint64(block.number);

        emit OperatorDeregisterStarted(msg.sender);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function finishDeregisterOperator() external registeredOperator(msg.sender) restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

        if (operator.startDeregisterOperatorBlock == 0) {
            revert DeregistrationNotStarted();
        }

        if (block.number < operator.startDeregisterOperatorBlock + $.deregistrationDelay) {
            revert DeregistrationDelayNotElapsed();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        delete $.operators[msg.sender];

        emit OperatorDeregistered(msg.sender);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function setOperatorCommitment(OperatorCommitment memory newCommitment)
        external
        registeredOperator(msg.sender)
        restricted
    {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operator = $.operators[msg.sender];

        if (operator.commitmentValidAfter != 0 && block.number >= operator.commitmentValidAfter) {
            operator.commitment = operator.pendingCommitment;
        }

        operator.pendingCommitment = newCommitment;
        operator.commitmentValidAfter = uint64(block.number) + $.deregistrationDelay;

        emit OperatorCommitmentChangeInitiated({
            operator: msg.sender,
            oldCommitment: operator.commitment,
            newCommitment: newCommitment,
            validAfter: operator.commitmentValidAfter
        });
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted to the DAO
     */
    function setDeregistrationDelay(uint64 newDelay) external restricted {
        _setDeregistrationDelay(newDelay);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted to the DAO
     */
    function updateAVSMetadataURI(string memory _metadataURI) external restricted {
        AVS_DIRECTORY.updateAVSMetadataURI(_metadataURI);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted to the DAO
     */
    function setAllowlistRestakingStrategy(address strategy, bool allowed) external restricted {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
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

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted to the OPERATIONS_MULTISIG
     */
    function submitOperatorRewards(IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions)
        external
        restricted
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

    function setClaimerFor(address claimer) external restricted {
        EIGEN_REWARDS_COORDINATOR.setClaimerFor(claimer);
    }

    // GETTERS

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getDeregistrationDelay() external view returns (uint64) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.deregistrationDelay;
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getOperator(address operator) external view returns (OperatorDataExtended memory) {
        return _getOperator(operator);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getValidator(bytes32 blsPubKeyHash) external view returns (ValidatorDataExtended memory) {
        return _getValidator(blsPubKeyHash);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getValidatorByIndex(uint256 validatorIndex) external view returns (ValidatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        bytes32 blsPubKeyHash = $.validatorIndexes[validatorIndex];
        return _getValidator(blsPubKeyHash);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getValidators(bytes32[] calldata blsPubKeyHashes) external view returns (ValidatorDataExtended[] memory) {
        uint256 blsPubKeyHashesLength = blsPubKeyHashes.length;
        ValidatorDataExtended[] memory validators = new ValidatorDataExtended[](blsPubKeyHashesLength);
        for (uint256 i = 0; i < blsPubKeyHashesLength; i++) {
            validators[i] = _getValidator(blsPubKeyHashes[i]);
        }
        return validators;
    }

    /**
     * @notice Checks if a given validator is committed to a particular chain ID,
     * by looking up its operator's active chain commitments.
     */
    function isValidatorInChainId(bytes32 blsPubKeyHash, uint256 chainId) external view returns (bool) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        ValidatorData storage validator = $.validators[blsPubKeyHash];

        // If the validator is never registered or is already deregistered, return false
        if (validator.index == 0 || block.number >= validator.registeredUntil) {
            return false;
        }

        // Check if the operator has the chainId in its active commitment
        OperatorData storage operatorData = $.operators[validator.operator];
        OperatorCommitment memory activeCommitment = _getActiveCommitment(operatorData);

        for (uint256 i = 0; i < activeCommitment.chainIds.length; i++) {
            if (activeCommitment.chainIds[i] == chainId) {
                return true;
            }
        }
        return false;
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (address[] memory restakedStrategies)
    {
        OperatorDataExtended memory operatorData = _getOperator(operator);
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

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

    /**
     * @inheritdoc IVerisenseAVSManager
     */
    function getRestakeableStrategies() external view returns (address[] memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        return $.allowlistedRestakingStrategies.values();
    }

    // INTERNAL FUNCTIONS

    function _getOperator(address operator) internal view returns (OperatorDataExtended memory) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        OperatorData storage operatorData = $.operators[operator];

        OperatorCommitment memory activeCommitment = _getActiveCommitment(operatorData);

        return OperatorDataExtended({
            validatorCount: operatorData.validatorCount,
            commitment: activeCommitment,
            pendingCommitment: operatorData.pendingCommitment,
            startDeregisterOperatorBlock: operatorData.startDeregisterOperatorBlock,
            isRegistered: _getAvsOperatorStatus(operator) == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED,
            commitmentValidAfter: operatorData.commitmentValidAfter
        });
    }

    function _getValidator(bytes32 blsPubKeyHash) internal view returns (ValidatorDataExtended memory validator) {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();

        ValidatorData memory validatorData = $.validators[blsPubKeyHash];

        if (validatorData.index != 0) {
            IEigenPod eigenPod = IEigenPod(validatorData.eigenPod);
            IEigenPod.ValidatorInfo memory validatorInfo = eigenPod.validatorPubkeyHashToInfo(blsPubKeyHash);

            bool backedByStake = EIGEN_DELEGATION_MANAGER.delegatedTo(eigenPod.podOwner()) == validatorData.operator;

            OperatorData storage operator = $.operators[validatorData.operator];
            OperatorCommitment memory activeCommitment = _getActiveCommitment(operator);

            return ValidatorDataExtended({
                operator: validatorData.operator,
                eigenPod: validatorData.eigenPod,
                validatorIndex: validatorInfo.validatorIndex,
                status: validatorInfo.status,
                delegateKey: activeCommitment.delegateKey,
                chainIds: activeCommitment.chainIds,
                backedByStake: backedByStake,
                registered: block.number < validatorData.registeredUntil
            });
        }
    }

    function _getActiveCommitment(OperatorData storage operatorData)
        internal
        view
        returns (OperatorCommitment memory)
    {
        if (operatorData.commitmentValidAfter != 0 && block.number >= operatorData.commitmentValidAfter) {
            return operatorData.pendingCommitment;
        }
        return operatorData.commitment;
    }

    /**
     * @dev Internal function to set or update the deregistration delay
     * @param newDelay The new deregistration delay to set
     */
    function _setDeregistrationDelay(uint64 newDelay) internal {
        UniFiAVSStorage storage $ = _getUniFiAVSManagerStorage();
        uint64 oldDelay = $.deregistrationDelay;
        $.deregistrationDelay = newDelay;

        emit DeregistrationDelaySet(oldDelay, newDelay);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
