# -- FILE: features/soak_01_active.feature
Feature: Transfer tokens from Sidechain to Mainchain
    Scenario: Verify cross-chain Tx from sidechain to mainchain (lock)
        Given we have a Sidechain node
        And we have a Cardano network socket
        # And we have the bridge contract deployed at cardano address
        # Either we generate new and fund them or we have them already funded
            # Generate new
        #And we have a funded sidechain account with at least 100,000,000 sidechain tokens
        #And we have a funded mainchain account with at least 505 tADA
            # Re-use
        And we have 10 sidechain addresses
        And we have 10 mainchain addresses
                Then the sum of the sidechain and mainchain accounts is 100M
                # Generate new
            #When we generate 10 sidechain accounts
            #And we fund those 10 sidechain accounts with 10M sidechain tokens each
            #When we generate 10 mainchain accounts
            #When we query for latest main chain status
            #And we fund those 10 mainchain accounts with 50 tADA each
            #    Then the sum of the sidechain and mainchain accounts is 100M
                # End generate new
            When we query for latest main chain status
            When we send 10 random sidechain token amounts between the 10 sidechain accounts
                Then the initial sum of sidechain tokens is equal to the final sum on the sidechain
            When we send a random amount of sidechain tokens from each sidechain account to a random one of the 10 mainchain accounts
                Then the total balance of the sidechain amount is reduced by the sum of tokens locked
            When we query the main chain status from the sidechain
                Then the transactions appear on the sidechain outgoing transactions
            When we wait until the sidechain phase has changed to the next handover
                Then the merkle root hashes of the transactions are obtained
            When we query for latest main chain status
            And we wait until the sidechain epoch has changed
            And we wait until the committee handover has happened
            And we claim the sidechain tokens of all lock txs on mainchain
                Then all the claims should be succesful
                And the sum of the sidechain and mainchain accounts is 100M
