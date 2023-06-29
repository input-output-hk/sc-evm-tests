# -- FILE: features/bridge.feature
Feature: Cardano-Sidechain bridge setup

    Scenario: Verify interface connection and network sync state for both chains
        Given we have a Sidechain node
        And we have another Sidechain node
        And we have a Cardano network socket
            When we query for latest Sidechain block
            Then we verify that its hash is the same on another node

            When we query for latest main chain status
            Then we verify that it is synced


    Scenario: Verify cardano connectivity with Sidechain
        Given we have a Sidechain node
        And we have a Cardano network socket
            When we query for latest main chain status
            And we query db-sync for latest block
            And we query the main chain status from the sidechain
                Then all three match
