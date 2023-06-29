# -- FILE: features/bridge_sidechain.feature
Feature: Cardano-Sidechain sidechain functionality


    Scenario: Verify last registration is active and last deregistration is removed
        Given we have a Sidechain node
            When we request the list of current candidates
            And we define which registration should be added and which removed
               Then the mainchain public key 1 is found as active in the list of candidates
               And the mainchain public key 2 is NOT found in the list of candidates

    Scenario: Verify cardano block producer registration / deregistration with bridge contract
        Given we have a Sidechain node
        And we have a Cardano network socket
        And we have the bridge contract deployed at cardano address
            When we query for latest main chain status
            And we request the list of current candidates
            And we define which registration should be added and which removed
            And we register a validator to the bridge contract on Cardano
            And we de-register another validator from the bridge contract on Cardano
            And we register a temporary validator to the bridge contract on Cardano
            And we request the list of current candidates
            And we de-register the temporary validator from the bridge contract on Cardano
            And we request the list of current candidates
                Then the validator is pending registration on the contract
                And the other validator is pending deregistration on the contract
                And the temporary validator is not registered on the contract

    Scenario: Verify requirement of minimal configurable stake from the candidates
        Given we have a Sidechain node
        And we have a Cardano network socket
        And we have the bridge contract deployed at cardano address
            When we query for latest main chain status
            And we request the list of current candidates
            And we register a validator with low pledge to the bridge contract on Cardano
            And we request the list of current candidates
                Then the low pledge validator is registered on the contract
            When we de-register a validator with low pledge from the bridge contract on Cardano
            And we request the list of current candidates
                Then the low pledge validator is not registered on the contract
                And the low pledge validator was registered as Invalid on the contract

