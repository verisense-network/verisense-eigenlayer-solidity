// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessManagedUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
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
        address eigenPodManagerAddress,
        address eigenDelegationManagerAddress,
        address avsDirectoryAddress,
        address rewardsCoordinatorAddress
    ) {
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
        _disableInitializers();
    }

    function initialize(address accessManager, uint64 initialDeregistrationDelay) public initializer {
        __AccessManaged_init(accessManager);
        _setDeregistrationDelay(initialDeregistrationDelay);
        // Initialize BEACON_CHAIN_STRATEGY as an allowed restaking strategy
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        $.allowlistedRestakingStrategies.add(BEACON_CHAIN_STRATEGY);
    }

    // EXTERNAL FUNCTIONS

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function registerOperator(ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature, bytes32 substrate_pubkey)
        external
        restricted
    {
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);
        _getVerisenseAVSManagerStorage().operators[msg.sender].substrate_pubkey = substrate_pubkey;
        _getVerisenseAVSManagerStorage().operatorAddresses.add(msg.sender);
        emit OperatorRegistered(msg.sender);
    }

    /**
     * @inheritdoc IVerisenseAVSManager
     * @dev Restricted in this context is like `whenNotPaused` modifier from Pausable.sol
     */
    function startDeregisterOperator() external registeredOperator(msg.sender) restricted {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();

        OperatorData storage operator = $.operators[msg.sender];

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
                key : d.substrate_pubkey,
                operator : key,
                stake : _getOperatorStake(key, strategies),
                isRegistered : _getAvsOperatorStatus(key) == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED
            });
            validators[i] = dv;
        }
        return validators;
    }

    function getOperatorRestakedStrategies(address operator)
        external
        view
        returns (address[] memory restakedStrategies)
    {
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

    /**
     * @dev Internal function to set or update the deregistration delay
     * @param newDelay The new deregistration delay to set
     */
    function _setDeregistrationDelay(uint64 newDelay) internal {
        VerisenseAVSStorage storage $ = _getVerisenseAVSManagerStorage();
        uint64 oldDelay = $.deregistrationDelay;
        $.deregistrationDelay = newDelay;
        emit DeregistrationDelaySet(oldDelay, newDelay);
    }

    function _authorizeUpgrade(address newImplementation) internal virtual override restricted { }
}
