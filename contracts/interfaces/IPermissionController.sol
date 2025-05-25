
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

interface IPermissionController {
    /**
 * @notice Sets a pending admin for an account.
     * @param account The account to set the pending admin for.
     * @param admin The address to set as pending admin.
     * @dev The pending admin must accept the role before becoming an active admin.
     * @dev Multiple admins can be set for a single account.
     */
    function addPendingAdmin(address account, address admin) external;
}