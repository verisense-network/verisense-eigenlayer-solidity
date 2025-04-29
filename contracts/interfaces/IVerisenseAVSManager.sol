// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IDelegationManager } from "eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import { ISignatureUtils } from "eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";
import { IAVSDirectory } from "eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import { IRewardsCoordinator } from "eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import { IEigenPod } from "eigenlayer-contracts/src/contracts/interfaces/IEigenPod.sol";
import { IEigenPodManager } from "eigenlayer-contracts/src/contracts/interfaces/IEigenPodManager.sol";

/**
 * @title IVerisenseAVSManager
 * @notice Interface for the VerisenseAVSManager contract, which manages operators and validators in the Verisense AVS.
 * @dev This interface defines the main functions and events for operator and validator management.
 */
interface IVerisenseAVSManager {
    /**
     * @title ValidatorData
     * @notice Struct to store information about a validator in the Verisense AVS system.
     * @dev This struct is used to keep track of important validator details.
     */
    struct ValidatorData {
        /// @notice The address of the EigenPod associated with this validator.
        address eigenPod;
        /// @notice The beacon chain validator index.
        uint64 index;
        /// @notice The address of the operator managing this validator.
        address operator;
        /// @notice The block number until which the validator is registered.
        uint64 registeredUntil;
    }

    struct OperatorValidData {
        address operator;
        uint256 stake;
        bytes32 substratePubkey;
        address[] restakedStrategies;
    }

    /**
     * @title OperatorData
     * @notice Struct to store information about an operator in the Verisense AVS system.
     * @dev This struct is used to keep track of important operator details.
     */
    struct OperatorData {
        /// @notice The block number when the operator started the deregistration process.
        uint64 startDeregisterOperatorBlock;
        /// @notice pubkey for substate block
        bytes32 substrate_pubkey;

        bool isRegistered;
    }

    /**
     * @title ValidatorDataExtended
     * @notice Struct to store comprehensive information about a validator.
     * @dev This struct combines ValidatorData with additional status information.
     */
    struct ValidatorDataExtended {
        /// @notice The address of the operator this validator is delegated to.
        address operator;
        /// @notice The address of the validator's EigenPod.
        address eigenPod;
        /// @notice The index of the validator in the beacon chain.
        uint64 validatorIndex;
        /// @notice The current status of the validator in the EigenPod.
        IEigenPod.VALIDATOR_STATUS status;
        /// @notice The delegate key currently associated with the validator's operator.
        bytes delegateKey;
        /// @notice Chain IDs the validator's operator is committed to.
        uint256[] chainIds;
        /// @notice Indicates whether the validator's EigenPod is currently delegated to the operator.
        bool backedByStake;
        /// @notice Indicates whether the validator is currently registered (current block < registeredUntil).
        bool registered;
    }

    /**
     * @title OperatorDataExtended
     * @notice Struct to store extended information about an operator in the Verisense AVS system.
     * @dev This struct combines OperatorData with additional status information.
     */
    struct OperatorDataExtended {
        /// @notice The block number when the operator started the deregistration process.
        uint128 startDeregisterOperatorBlock;
        /// @notice Whether the operator is registered or not.
        bool isRegistered;
    }
    // 7 bytes padding here (automatically added by the compiler)

    /// @notice Thrown when an operator attempts to deregister while still having validators
    error OperatorHasValidators();

    /// @notice Thrown when a non-operator attempts an operator-only action
    error NotOperator();

    /// @notice Thrown when an EigenPod does not exist for a given address
    error NoEigenPod();

    /// @notice Thrown when trying to finish deregistering an operator before the delay has elapsed
    error DeregistrationDelayNotElapsed();

    /// @notice Thrown when attempting to start deregistering an operator that has already started
    error DeregistrationAlreadyStarted();

    /// @notice Thrown when trying to finish deregistering an operator that hasn't started
    error DeregistrationNotStarted();

    /// @notice Thrown when an address is not delegated to the expected operator
    error NotDelegatedToOperator();

    /// @notice Thrown when a validator is not in the active state
    error ValidatorNotActive();

    /// @notice Thrown when an action requires a registered operator, but the operator is not registered
    error OperatorNotRegistered();

    /// @notice Thrown when a non-operator attempts to deregister a validator
    error NotValidatorOperator();

    /// @notice Thrown when attempting to register a validator that is already registered
    error ValidatorAlreadyRegistered();

    /// @notice Thrown when an operator's delegate key is not set
    error DelegateKeyNotSet();

    /// @notice Thrown when trying to update an operator commitment before the change delay has passed
    error CommitmentChangeNotReady();

    /// @notice Thrown when attempting to deregister a validator that is already deregistered
    error ValidatorAlreadyDeregistered();

    /// @notice Thrown when a restaking strategy allowlist update fails
    error RestakingStrategyAllowlistUpdateFailed();

    /// @notice Thrown when an AVS operator status call fails
    error AVSOperatorStatusCallFailed();

    /// @notice Thrown when an invalid EigenPodManager address is provided
    error InvalidEigenPodManagerAddress();

    /// @notice Thrown when an invalid EigenDelegationManager address is provided
    error InvalidEigenDelegationManagerAddress();

    /// @notice Thrown when an invalid AVSDirectory address is provided
    error InvalidAVSDirectoryAddress();

    /// @notice Thrown when an invalid RewardsCoordinator address is provided
    error InvalidRewardsCoordinatorAddress();

    /**
     * @notice Emitted when a new operator is registered in the Verisense AVS.
     * @param operator The address of the registered operator.
     */
    event OperatorRegistered(address indexed operator);

    /**
     * @notice Emitted when a new validator is registered in the Verisense AVS .
     * @param podOwner The address of the validator's EigenPod owner.
     * @param delegateKey The delegate public key for the validator.
     * @param blsPubKeyHash The BLS public key hash of the validator.
     * @param validatorIndex The beacon chain validator index.
     */
    event ValidatorRegistered(
        address indexed podOwner,
        address indexed operator,
        bytes delegateKey,
        bytes32 blsPubKeyHash,
        uint256 validatorIndex
    );

    /**
     * @notice Emitted when an operator starts the deregistration process.
     * @param operator The address of the operator starting deregistration.
     */
    event OperatorDeregisterStarted(address indexed operator);

    /**
     * @notice Emitted when an operator is deregistered from the Verisense AVS.
     * @param operator The address of the deregistered operator.
     */
    event OperatorDeregistered(address indexed operator);

    /**
     * @notice Emitted when a validator is deregistered from the Verisense AVS.
     * @param operator The address of the operator managing the validator.
     * @param blsPubKeyHash The BLS public key hash of the deregistered validator.
     */
    event ValidatorDeregistered(address indexed operator, bytes32 blsPubKeyHash);


    /**
     * @notice Emitted when the deregistration delay is updated.
     * @param oldDelay The previous deregistration delay value.
     * @param newDelay The new deregistration delay value.
     */
    event DeregistrationDelaySet(uint64 oldDelay, uint64 newDelay);

    /**
     * @notice Emitted when a restaking strategy is added or removed from the allowlist.
     * @param strategy The address of the strategy.
     * @param allowed Whether the strategy is allowed (true) or disallowed (false).
     */
    event RestakingStrategyAllowlistUpdated(address indexed strategy, bool allowed);

    /**
     * @notice Emitted when operator rewards are submitted.
     */
    event OperatorRewardsSubmitted();

    /**
     * @notice Returns the EigenPodManager contract.
     * @return IEigenPodManager The EigenPodManager contract.
     */
    function EIGEN_POD_MANAGER() external view returns (IEigenPodManager);

    /**
     * @notice Returns the EigenDelegationManager contract.
     * @return IDelegationManager The EigenDelegationManager contract.
     */
    function EIGEN_DELEGATION_MANAGER() external view returns (IDelegationManager);

    /**
     * @notice Returns the AVSDirectory contract.
     * @return IAVSDirectory The AVSDirectory contract.
     */
    function AVS_DIRECTORY() external view returns (IAVSDirectory);

    /**
     * @notice Registers a new operator in the Verisense AVS.
     * @param operatorSignature The signature and associated data for operator registration.
     */
    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature, bytes32 substrate_pubkey) external;

    /**
     * @notice Starts the process of deregistering an operator from the Verisense AVS.
     */
    function startDeregisterOperator() external;

    /**
     * @notice Finishes the process of deregistering an operator from the Verisense AVS.
     */
    function finishDeregisterOperator() external;

    /**
     * @notice Updates the metadata URI for the AVS
     * @param _metadataURI is the metadata URI for the AVS
     */
    function updateAVSMetadataURI(string memory _metadataURI) external;

    /**
     * @notice Sets a new deregistration delay for operators.
     * @param newDelay The new deregistration delay in seconds.
     * @dev Restricted to the DAO
     */
    function setDeregistrationDelay(uint64 newDelay) external;

    /**
     * @notice Add or remove a strategy address from the allowlist of restaking strategies
     * @param strategy The address of the strategy to add or remove
     * @param allowed Whether the strategy should be allowed (true) or disallowed (false)
     * @dev Restricted to the DAO
     */
    function setAllowlistRestakingStrategy(address strategy, bool allowed) external;

    /**
     * @notice Retrieves information about a specific operator.
     * @param operator The address of the operator.
     * @return OperatorDataExtended struct containing information about the operator.
     */
    function getOperator(address operator) external view returns (OperatorDataExtended memory);

    /**
     * @notice Retrieves the current deregistration delay for operators.
     * @return The current deregistration delay in seconds.
     */
    function getDeregistrationDelay() external view returns (uint64);

    /**
     * @notice Returns the list of strategies that the operator has potentially restaked on the AVS
     * @param operator The address of the operator to get restaked strategies for
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on whether the operator has shares for a strategy in a quorum or uniqueness
     *      of each element in the returned array. The off-chain service should do that validation separately
     */
    function getOperatorRestakedStrategies(address operator) external view returns (address[] memory);

    /**
     * @notice Returns the list of strategies that the AVS supports for restaking
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on uniqueness of each element in the returned array.
     *      The off-chain service should do that validation separately
     */
    function getRestakeableStrategies() external view returns (address[] memory);

    /**
     * @notice Submits EigenLayer rewards for operators.
     * @param eraIndex The era index of submissions.
     * @param submissions The array of rewards submissions.
     */
    function submitOperatorRewards(uint256 eraIndex, IRewardsCoordinator.OperatorDirectedRewardsSubmission[] calldata submissions)
        external;

    function LatestRewardedEra() external view returns (uint256);

    /**
     * @notice Sets the claimer for the AVS to get excess rewards back.
     * @param claimer The address of the claimer.
     */
    function setClaimerFor(address claimer) external;
}
