// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Structure to hold order details; provided externally in case consumer
// contracts need to import for interaction. Delivered when an order is opened.
struct LimitOrder {
    uint256 fee;        // Fee associated with the order.
    uint256 blocknum;   // Block number that this order was delivered.
    bool executed;      // Whether the order has been executed.
}

/**
 * @notice An exchange contract that hosts (in current version) a single pool. Pool is
 * kept secure from market orders. Traders *must* make stealthy limit orders, placed using
 * a hash of the actual order details, and executed *at least* some number of blocks later
 * once limit is reached.
 *
 * Enables immunity for the exchange from frontrunning and stop loss hunting.
 *
 * @dev A few notes:
 * - Traders can have multiple orders open at a time, but may run into execution issues
 * if limits are clustered too tightly.
 * - Fees are optionally used for payments to relayers. This introduces trust into the
 * process between trader and relayer, but provides an avenue for traders seeking to
 * minimize their on-chain activity or utilize a third-party service to add another layer
 * of stealth.
 * - The actual limit price in the limit order is a signed integer, with negative values
 * indicating a 'sell' (swap asset -> stable) and positive values indicating a 'buy' (swap
 * stable -> asset).
 */
contract Enigma {
    // A reasonable range.
    uint256 public constant MIN_PARITY = 1;
    uint256 public constant MAX_PARITY = 10;
    // The parity requirement between opening and executing for the pool in blocks.
    uint256 public immutable PARITY_REQ;

    // TODO: Support multiple pools.
    // TODO: Support any-any tokens.
    // Tokens in the stable <> asset pool.
    IERC20 public stable;
    IERC20 public asset;

    // Mapping of traders to encrypted order limit hashes to opened order details.
    mapping(address => mapping(bytes32 => LimitOrder)) public orders;

    // Event to emit when an order is opened.
    event OrderOpened(bytes32 indexed encrypted, address indexed trader, uint256 fee);
    // Event to emit when an order is executed.
    event OrderExecuted(bytes32 indexed encrypted, address indexed trader);

    /**
     * @notice Init Enigma.
     * @param _stable - A valid stablecoin ERC20 address. Stablecoin status is not verified,
     * thus should be established by consumers of the instance independently.
     * @param _asset - The traded asset.
     * @param _parity - The parity requirement between opening and executing for the pool in
     * blocks.
     */
    constructor(address _stable, address _asset, uint256 _parity) {
        stable = IERC20(_stable);
        asset = IERC20(_asset);

        require(_parity >= MIN_PARITY && _parity <= MAX_PARITY, "Parity given not within min/max range.");
        PARITY_REQ = _parity;
    }

    /// READ METHODS

    // TODO: Method for read prices, read from orders placed (e.g. read fee, block).

    /// WRITE METHODS

    /**
     * @notice Opens an encrypted limit order, obfuscating the trader's levels. Order
     * can be executed when the limit condition is met. Can go in either direction; in
     * the direction of asset > stable, mimics a stop loss. The sender is considered the
     * trader who placed the order.
     * @dev The fee will be msg.value. It *can* be zero, which indicates a relayer is
     * unlikely to execute on the trader's behalf and the trader will have to execute
     * themselves.
     * @param encrypted - Hashed limit price in stablecoin at which order may be executed.
     */
    function open(bytes32 encrypted) external {
        uint256 fee = msg.value;
        orders[msg.sender][encrypted] = LimitOrder({
            fee: fee,
            blocknum: block.number
        });

        emit OrderOpened(encrypted, msg.sender, fee);
    }

    /**
     * @notice Executes a limit order. Direct submission from trader.
     * @param encrypted - Hashed limit price in stablecoin.
     * @param limit - The actual limit in stablecoin.
     * @dev Limit is a signed integer. If negative, it indicates we are selling, positive
     * indicates buying.
     */
    function execute(bytes32 encrypted, int256 limit) external {
        LimitOrder memory order = orders[msg.sender][encrypted];

        execute(order);

        // Check if there's a fee and pay out to caller.
        if (order.fee > 0) {
            msg.sender.call{value: order.fee}("");
        }
    }

    /**
     * @notice Executes a limit order. Indirect submission from relayer on trader's behalf,
     * requiring signature.
     */
    function execute(bytes32 encrypted, int256 limit, bytes memory signature) external {
        // Decrypt the provided signature to get the trader address.
        bytes32 digest = keccak256(abi.encodePacked(limit));
        address trader = recoverSigner(message, signature);

        LimitOrder memory order = orders[trader][encrypted];

        // Check to make sure order exists.
        require(order.blocknum == 0, "Order does not exist.");

        execute(order); // 66

        // Check if there's a fee and pay out to caller.
        if (order.fee > 0) {
            msg.sender.call{value: order.fee}("");
        }
    }

    /**
     * @notice Executes a limit order. This private function is to be called from either
     * of the public endpoints for execute.
     */
    function execute(LimitOrder memory order) private {
        LimitOrder storage order = orders[_orderHash];

        // TODO:
        // Check for market conditions and execution logic here...

        // TODO:
        // Logic to swap tokens based on order details would go here...

        emit OrderExecuted(_orderHash, msg.sender);
    }

    /// UTILITY METHODS

    /**
     * @notice Helper method for splitting a signature and doing ecrecover to get the
     * signature's signer address.
     * @param message - 32-byte message data.
     * @param signature - Signature bytes.
     */
    function recoverSigner(bytes32 message, bytes memory signature)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

        return ecrecover(message, v, r, s);
    }

    /**
     * @notice Split a signature into a 3-tuple of v, r, s parts/coordinates.
     * @param signature - The signature from which to derive v, r, s.
     */
    function splitSignature(bytes memory signature)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(signature.length == 65, "Incorrect signature length.");

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(signature, 32))
            // second 32 bytes.
            s := mload(add(signature, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(signature, 96)))
        }

        return (v, r, s);
    }
}
