// SPDX-License-Identifier: MIT
pragma solidity ^0.8.14;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

// Structure to hold order details; provided externally in case consumer
// contracts need to import for interaction. Delivered when an order is opened.
struct EnigmaLimitOrder {
    uint256 fee;        // Fee associated with the order.
    uint256 blocknum;   // Block number that this order was delivered.
    bool executed;      // Whether the order has been executed.
}

// Structure to represent the token pool.
struct EnigmaTokenPool {
    uint256 stableBalance;  // The balance of stablecoin tokens in the pool.
    uint256 assetBalance;   // The balance of non-stable asset in the pool.
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
contract Enigma is AccessControl {
    // A reasonable range.
    uint256 public constant MIN_PARITY = 1;
    uint256 public constant MAX_PARITY = 10;
    // Another reasonable range.
    uint256 public constant MIN_TAU = 12 hours;
    uint256 public constant MAX_TAU = 168 hours;
    // Used in pause initiation time calculation. Kind of risky with how the EVM
    // improves this aspect over time.
    uint256 private constant AVG_BLOCK_TIME_SECONDS = 14;

    // The parity requirement between opening and executing for the pool in blocks.
    uint256 public immutable PARITY;
    // The time requirement *in number of blocks* from pause initiation to enaction.
    uint256 public immutable TAU;

    // TODO: Support any-any tokens.
    // Tokens in the stable <> asset pool.
    IERC20 public stable;
    IERC20 public asset;

    // TODO: Support multiple pools.
    // Token pool tracking the token balances.
    TokenPool public pool;

    // Mapping of traders to encrypted order limit hashes to opened order details.
    mapping(address => mapping(bytes32 => EnigmaLimitOrder)) public orders;

    // When the system was paused, enabling AMMs to deposit liquidity. If current block
    // number is less than this, system is considered to be unpaused.
    uint256 public paused;

    // Event to emit when an order is opened.
    event OrderOpened(bytes32 indexed encrypted, address indexed trader, uint256 fee);
    // Event to emit when an order is executed.
    event OrderExecuted(bytes32 indexed encrypted, address indexed trader);

    /**
     * @notice Init Enigma. Note that the contract starts paused to enable AMMs to deposit
     * initial liquidity.
     * @param _stable - A valid stablecoin ERC20 address. Stablecoin status is not verified,
     * thus should be established by consumers of the instance independently.
     * @param _asset - The traded asset.
     * @param _parity - The parity requirement between opening and executing for the pool in
     * blocks.
     * @param _tau - The amount of time *in seconds* required between initiating a pause
     * and pausing.
     */
    constructor(address _stable, address _asset, uint256 _parity, uint256 _tau) {
        stable = IERC20(_stable);
        asset = IERC20(_asset);

        require(
            _parity >= MIN_PARITY && _parity <= MAX_PARITY,
            "Parity given not within min/max range."
        );
        PARITY_REQ = _parity;

        require(
            _tau >= MIN_TAU && _tau <= MAX_TAU,
            "Tau given not within min/max range."
        );
        tau = _tau / AVG_BLOCK_TIME_SECONDS;

        // Start the system paused so AMMs can add initial liquidity.
        paused = block.number;

        // Add global admin role.
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Modifier that allows function execution only when the contract is *not* paused.
     */
    modifier whenNotPaused() {
        require(block.number < paused, "Contract is paused.");
        _;
    }

    /**
     * @notice Modifier that allows function execution only when the contract *is* paused.
     */
    modifier whenPaused() {
        require(block.number >= paused, "Contract is not paused.");
        _;
    }

    /// READ METHODS

    // TODO: Method for reading from orders placed (e.g. read fee, block).

    /**
     * @notice Retrieves the current price of the asset in terms of stablecoin. This
     * function assumes price is a direct ratio of stablecoin to asset balance.
     * In real scenarios, you may want to adjust this to include fees, slippage, or
     * use an external price oracle.
     */
    function getPrice() public view returns (uint256) {
        // Price is defined as stableBalance / assetBalance.
        // Ensure no division by zero.
        require(pool.assetBalance > 0, "Asset balance is zero, cannot determine price.");
        return pool.stableBalance / pool.assetBalance;
    }

    /**
     * @notice Returns whether the system is currently paused.
     */
    function isPaused() external view {
        return paused >= block.number;
    }

    /// AMM DEPOSIT METHODS

    /**
     * @notice To be called by owner to initiate a pause cycle.
     */
    function initiatePause() external onlyOwner {
        paused = block.number + TAU;
    }

    /**
     * @notice To be called by owner to end a pause cycle.
     */
    function removePause() external onlyOwner {
        paused = 0;
    }

    /**
     * @notice To be called by AMMs to deposit stablecoin tokens into the pool.
     */
    function depositStable(uint256 amount) public whenNotPaused {
        require(
            stable.transferFrom(msg.sender, address(this), amount),
            "Transfer failed."
        );
    }

    /**
     * @notice To be called by AMMs to deposit asset tokens into the pool.
     */
    function depositAsset(uint256 amount) public whenNotPaused {
        require(
            asset.transferFrom(msg.sender, address(this), amount),
            "Transfer failed."
        );
    }

    /// LIMIT ORDER METHODS

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
        orders[msg.sender][encrypted] = EnigmaLimitOrder({
            fee: fee,
            blocknum: block.number
        });

        emit OrderOpened(encrypted, msg.sender, fee);
    }

    // TODO: Cancel method

    /**
     * @notice Executes a limit order. Direct submission from trader.
     * @dev Limit is a signed integer. If negative, it indicates we are selling, positive
     * indicates buying.
     * @param encrypted - Hashed limit price in stablecoin.
     * @param limit - The actual limit in stablecoin.
     */
    function execute(bytes32 encrypted, int256 limit) external whenNotPaused {
        // We check for pool conditions here, first thing, to save gas on executions
        // where the price might retrace back across the limit line.
        assertLimitIsMet(limit);

        EnigmaLimitOrder memory order = orders[msg.sender][encrypted];

        execute(order, encrypted, limit);

        emit OrderExecuted(encrypted, msg.sender);
    }

    /**
     * @notice Executes a limit order. Indirect submission from relayer on trader's behalf,
     * requiring signature.
     */
    function execute(
        bytes32 encrypted,
        int256 limit,
        bytes memory signature
    ) external whenNotPaused {
        // We check for pool conditions here, first thing, to save gas on executions
        // where the price might retrace back across the limit line.
        assertLimitIsMet(limit);

        // Decrypt the provided signature to get the trader address.
        bytes32 digest = keccak256(abi.encodePacked(limit));
        address trader = recoverSigner(message, signature);

        EnigmaLimitOrder memory order = orders[trader][encrypted];

        execute(order /** 66 */, encrypted, limit);

        emit OrderExecuted(encrypted, trader);
    }

    /**
     * @notice Executes a limit order. This private function is to be called from either
     * of the public endpoints for execute.
     * @param order - The limit order placed prior.
     * @param encrypted - The limit value's submitted encrypted value.
     * @param limit - The actual target limit price to execute.
     */
    function execute(EnigmaLimitOrder memory order, bytes32 encrypted, int256 limit) private {
        // Ensure encrypted matches limit.
        require(
            encrypted == keccak256(limit),
            "Hash value for limit price does not match committed."
        );

        // Check to make sure order exists.
        assertOrderExists(order);

        // Ensure parity is met.
        require(
            block.number - order.blocknum >= PARITY, "Parity not met."
        );

        // TODO:
        // Logic to swap tokens based on order details would go here...


        // Check if there's a fee and pay out to caller.
        if (order.fee > 0) {
            msg.sender.call{value: order.fee}("");
        }
    }

    /// UTILITY METHODS

    /**
     * @notice Check whether the pool conditions are met for the limit to merit execution.
     * @param limit - Signed integer limit value.
     */
    function assertOrderExists(EnigmaLimitOrder memory order) private {
        require(order.blocknum != 0, "Order does not exist.");
    }

    /**
     * @notice Check whether the pool conditions are met for the limit to merit execution.
     * @param limit - Signed integer limit value.
     */
    function assertLimitMet(int256 limit) private {
        if (limit < 0) {
            // If sign is negative, it's the price at which to sell (asset -> stable).
            // Here, `limit` is negative, so we compare with its inverted value.
            require(price >= uint256(-limit), "Current price is too low to sell.");
        } else {
            // If sign is positive, it's the price at which to buy (stable -> asset).
            require(price <= uint256(limit), "Current price is too high to buy.");
        }
    }

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
