# -- FILE: features/bridge_interaction.feature
Feature: Cardano Interaction
    Scenario: Verify endpoint sidechain_getStatus
        Given we have a Sidechain node
        And we have a Cardano network socket
            When we query for latest main chain status
            And we query the main chain status from the sidechain
                Then Cardano block matches mainchain block from sidechain
                And Cardano tip matches mainchain tip from sidechain
                And Cardano epoch matches mainchain epoch from sidechain

    Scenario: Bridge contract registrations
        Given we have a Sidechain node
            When we request the list of candidates
            And we request the committee
                Then the committee members are a subset of the candidates
            When we request the current epoch
            And we request the committee of previous epochs
            And we request the epoch signatures of those previous epochs
                Then all honest committee members have signed handover and transactions

