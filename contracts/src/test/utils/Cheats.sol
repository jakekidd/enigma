// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.14;

abstract contract Cheats {
    // sets the block timestamp to x
    function warp(uint256 x) public virtual;

    // sets the block number to x
    function roll(uint256 x) public virtual;

    // sets the slot loc of contract c to val
    function store(
        address c,
        bytes32 loc,
        bytes32 val
    ) public virtual;

    function ffi(string[] calldata) external virtual returns (bytes memory);

    function expectEmit(
        bool,
        bool,
        bool,
        bool
    ) external virtual;

    function expectRevert(bytes calldata msg) external virtual;
}
