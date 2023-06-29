# -- FILE: features/soak_02_passive.feature
Feature: Transfer tokens from Mainchain to Sidechain
    Scenario: Verify cross-chain Tx from mainchain to sidechain (burn)
        Given we have a Sidechain node
        And we have a Cardano network socket
        And we have 10 mainchain addresses
        And we have 10 sidechain addresses
            When we query for latest main chain status
                Then the sum of the sidechain and mainchain accounts is 100M
            When we send 10 random sidechain token amounts between the 10 mainchain accounts
                Then the initial sum of sidechain tokens is equal to the final sum on the mainchain
            When we send a random amount of sidechain tokens from each mainchain account to a random one of the 10 sidechain accounts
                Then sidechain token transactions are identified as pending
            When we query the main chain status from the sidechain
            And we wait until best block becomes stable
                Then sidechain token transactions are no longer pending
            When we wait until sidechain token transactions are no longer queued
                Then the sum of the sidechain and mainchain accounts is 100M