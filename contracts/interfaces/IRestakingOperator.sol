// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title IRestakingOperator
 * @author Puffer Finance
 * @custom:security-contact security@puffer.fi
 */
interface IRestakingOperator {
    /**
     * @notice Updates a signature proof by setting the signer address of the message hash
     * @param digestHash is message hash
     * @param signer is the signer address
     * @dev Restricted to the PufferModuleManager
     */
    function updateSignatureProof(bytes32 digestHash, address signer) external;

    /**
     * @notice Does a custom call to `target` with `customCalldata`
     * @return response
     */
    function customCalldataCall(address target, bytes calldata customCalldata)
        external
        returns (bytes memory response);
}
