# Enigma

Enigma is an exchange contract with an ecosystem of traders (and relayers). It hosts a stablecoin <> asset pool. Any swaps performed - which must be through the Enigma contract - are immune to frontrunning and stop-loss hunting through usage of a commit/reveal scheme and execution requirements.

The "Trader" agent is a program written in Rust to monitor pool price to watch for limit being reached.

Some notes:
* Immediate market orders for swaps cannot be placed. Traders *must* deliver limit orders in the form of a hashed signed integer representing the limit price for execution.
* The sign of the limit price integer indicates a sell (negative) or buy (positive).
* The order may be executed *at least* some number of blocks later. The number is set permanently in the constructor.
* An optional fee can be used if the trader wishes to utilize a third-party relayer service.
* Traders can have multiple limit orders open at a time.
* Market inefficiencies can be corrected with a sort of "delayed market order" - essentially a limit order, but placed with the limit already exceeded. It will still have to wait the parity number of blocks.
