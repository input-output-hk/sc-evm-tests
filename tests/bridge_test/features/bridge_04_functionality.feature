# -- FILE: features/bridge_functionality.feature
Feature: Cardano-Sidechain bridge functionality
    Scenario: Verify cross-chain Tx from sidechain to mainchain
        Given we have a Sidechain node
        And we have a Cardano network socket
        And we have a funded Sidechain address with at least 10 tokens plus gas fees
        And we have a Cardano address with x sidechain tokens with policy ID
            When we query the main chain status from the sidechain
            And we lock 10 sidechain tokens on the sidechain contract
                Then the transaction appears on the sidechain outgoing transactions
            When we wait until the sidechain phase has changed to the next handover
                Then the merkle root hash of the transaction is obtained
            When we query for latest main chain status
            And we wait until the sidechain epoch has changed
            And we wait until the committee handover has happened
            And we claim the sidechain tokens on mainchain
                Then the claim should be succesful
                And the cardano address balance of sidechain token with policy ID equals to x + 10
            When we claim the sidechain tokens on mainchain
                Then the claim should fail
                And the cardano address balance of sidechain token with policy ID equals to x + 10
            When we try to lock more sidechain tokens than sidechain account's balance
                Then the lock operation fails


    Scenario: Verify cross-chain Tx from mainchain to sidechain
        Given we have a Sidechain node
        And we have a Cardano network socket
        And we have a funded Cardano address
        And we have a Cardano address with at least 10 tokens with policy ID
        And we have a Sidechain address
        And we have the bridge contract deployed at cardano address
            When we send 10 sidechain tokens from Cardano network to Sidechain address
                Then the sidechain token transaction is identified as pending
            When we query the main chain status from the sidechain
            And we wait until best block becomes stable
                Then Sidechain address balance increases by 10
                And the transaction appears in the list of incoming transactions
