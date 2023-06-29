# -- FILE: features/steps/bridge_steps.py
from behave import given, when, then
from behave import __main__ as runner_with_options
import os
import sys
import argparse
import bridge_api
import time
import math

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
bridge_dir = os.path.dirname(parent)
tests_folder_path = os.path.dirname(os.path.dirname(bridge_dir))
sys.path.append(tests_folder_path)
from utils import utils, cardano_cli
import utils.log_wrapper as logger
from models.sc_evm.burn_tx import BurnTx

NO_OF_PREV_EPOCHS_TO_TEST = 10
BEST_BLOCK_TOLERANCE = 6
LATEST_TIP_TOLERANCE = 100
MC_SC_TOKEN_RATIO = pow(10, 9)
TOKENS_TO_SEND = 10


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config-file",
        default="bridge-config.json",
        dest="config",
        help="Provide configuration file",
        type=str,
    )
    args = parser.parse_args()

    os.chdir(parent)
    result = runner_with_options.main(
        [
            "--define",
            f"config_file={args.config}",
            "--no-capture",
            "--no-capture-stderr",
            "--no-logcapture",
            "-s",  # Enable this for debugging mode
            "--format=pretty",
            "--include",
            "bridge",
            # '--include', 'bridge_01',  # Enable one at a time or disable all
            # '--include', 'bridge_02',
            # '--include', 'bridge_03',
            # '--include', 'bridge_04',
        ]
    )
    sys.exit(result)


######################################################################
############################### GIVEN ################################
######################################################################


@given("we have a Sidechain node")
def step_impl(context):
    try:
        network_version = int(context.ethRPC.net_version().__str__())
        assert network_version == int(
            context.ctl_params["sidechainParameters"]["chainId"]
        ), f"ERROR: Network version mismatch: {network_version} != \
           {context.ctl_params['sidechainParameters']['chainId']}"
    except Exception as e:
        assert False, e


@given("we have another Sidechain node")
def step_impl(context):
    try:
        network_version = int(context.ethRPC2.net_version().__str__())
        assert network_version == int(
            context.ctl_params["sidechainParameters"]["chainId"]
        ), f"ERROR: Network version mismatch: {network_version} != \
           {context.ctl_params['sidechainParameters']['chainId']}"
    except Exception as e:
        assert False, e


@given("we have a Cardano network socket")
def step_impl(context):
    # Override feature input:
    socket = context.bridge_params["mainchain_socket"]
    # Assert socket exists
    assert os.path.exists(socket), f"ERROR: Cardano socket not found at {socket}"


@given("we have the bridge contract deployed at cardano address")
def step_impl(context):
    # Call nix run .#ctl-main -- addresses with arguments from CTL's config.json
    #  and verify that they match with the given contract address
    context.sidechain_genesis_hash = bridge_api.getGenesisHash(
        context.sidechain_cli, context.bridge_params["sc_genesis_file"]
    )
    assert (
        context.sidechain_genesis_hash
        == context.ctl_params["sidechainParameters"]["genesisHash"]
    ), f"ERROR: genesis hash provided does not match genesis.json\n \
        From conf: {context.ctl_params['sidechainParameters']['genesisHash']}\n \
        From file: {context.sidechain_genesis_hash}"
    contract_address, policy_id = bridge_api.get_contract_addresses(
        context.trustless_ctl_cli,
        context.bridge_params["mc_payment_skey_file"],
        context.ctl_params["sidechainParameters"]["genesisUtxo"],
        context.ctl_params["sidechainParameters"]["chainId"],
        context.sidechain_genesis_hash,
        context.ctl_params["sidechainParameters"]["genesisMint"],
        context.ctl_params["sidechainParameters"]["threshold"]["numerator"],
        context.ctl_params["sidechainParameters"]["threshold"]["denominator"],
    )
    assert (
        context.bridge_params["mc_bridge_contract_addr"] == contract_address
    ), f"ERROR: Contract address {contract_address} not found"
    assert (
        context.bridge_params["mc_sc_token_policy_id"] == policy_id
    ), f"ERROR: Sidechain token policy ID mismatch:\n \
           Config: {context.bridge_params['mc_sc_token_policy_id']}\n \
           CTL: {policy_id}"


@given("we have a Cardano address with x sidechain tokens with policy ID")
def step_impl(context):
    context.receiving_cardano_addr_sc_token_balance = bridge_api.getSCTokenBalanceOnMC(
        context, context.mc_sc_token_addr
    )


@given("we have a funded Cardano address")
def step_impl(context):
    utxos = cardano_cli.getAddrUTxOs(
        context.mc_sc_token_addr, context.bridge_params["mainchain_network"]
    )
    assert (
        utxos is not False
    ), f"ERROR: Could not get UTxOs of address {context.mc_sc_token_addr}"
    tokensDict = cardano_cli.getTokenListFromTxHash(utxos)
    # 1.444443 for native token transfer + network fees
    assert (
        tokensDict["ADA"] > 1644443
    ), f"ERROR: Insufficient balance on address {context.mc_sc_token_addr}"
    context.tokensDict = tokensDict


@given("we have a Cardano address with at least 10 tokens with policy ID")
def step_impl(context):
    try:
        assert (
            context.tokensDict[context.bridge_params["mc_sc_token_policy_id"]]
            >= TOKENS_TO_SEND
        ), f"ERROR: Not enough tokens. Balance: \
            {context.tokensDict[context.bridge_params['mc_sc_token_policy_id']]}"
    except Exception as e:
        assert (
            False
        ), f"ERROR: could not find tokens with policy ID \
            {context.bridge_params['mc_sc_token_policy_id']},\n \
            in UTxOs {context.tokensDict}'\n {e}"


@given("we have a Sidechain address")
def step_impl(context):
    context.receiving_sc_evm_addr = context.sc_payment_addr
    receiving_sc_evm_balance = context.ethRPC.eth_getBalance(
        context.receiving_sc_evm_addr, "latest"
    ).__str__()
    assert utils.is_hex(
        receiving_sc_evm_balance
    ), f"ERROR: Balance returned in unknown format: {receiving_sc_evm_balance}"
    context.receiving_sc_evm_balance = int(receiving_sc_evm_balance, 16)


@given("we have a funded Sidechain address with at least 10 tokens plus gas fees")
def step_impl(context):
    sending_sc_evm_balance = context.ethRPC.eth_getBalance(
        context.sc_payment_addr, "latest"
    ).__str__()
    assert utils.is_hex(sending_sc_evm_balance), "ERROR: Balance return unknown format"
    assert (
        int(sending_sc_evm_balance, 16)
        >= TOKENS_TO_SEND * MC_SC_TOKEN_RATIO + 2 * 10**4
    ), f"ERROR: Balance less than {TOKENS_TO_SEND*MC_SC_TOKEN_RATIO} + \
        gas fees in gwei: {int(sending_sc_evm_balance, 16)}"


######################################################################
################################ WHEN ################################
######################################################################


@when("we query for latest Sidechain block")
def step_impl(context):
    latest_sc_evm_block = context.ethRPC.eth_getBlockByNumber("latest")
    assert utils.is_hex(latest_sc_evm_block["hash"])
    context.latest_sc_evm_block_hash = latest_sc_evm_block["hash"]


@when("we query for latest main chain status")
def step_impl(context):
    bridge_api.get_latest_mc_status(context)


@when("we query the main chain status from the sidechain")
def step_impl(context):
    bridge_api.get_mc_status_from_sc(context)
    context.last_tx_mc_best_block = context.cardano_best_block_from_SC


@when("we request the current epoch")
def step_impl(context):
    try:
        mc_info = context.ethRPC.sidechain_getStatus()
        context.sidechain_epoch = mc_info["sidechain"]["epoch"]
    except Exception as e:
        assert False, f"ERROR: Could not get sidechain current epoch: {e}"
    assert True


###################### bridge_02_sidechain.feature ###################
@when("we request the list of current candidates")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)
    try:
        context.current_candidates = eval(
            context.ethRPC.sidechain_getCurrentCandidates().__str__()
        )
    except Exception as e:
        assert False, f"ERROR: Could not get list of sidechain current candidates: {e}"
    assert (
        type(context.current_candidates) == list
    ), f"ERROR: Current candidates not a list: {context.current_candidates}"


@when("we define which registration should be added and which removed")
def step_impl(context):
    registration1Active = False
    registration2Active = False
    for candidate in context.current_candidates:
        if (
            context.ctl_params["registration1"]["spo-public-key"]
            in candidate["mainchainPubKey"]
            and candidate["registrationStatus"] == "Active"
        ):
            registration1Active = True
            continue
        if (
            context.ctl_params["registration2"]["spo-public-key"]
            in candidate["mainchainPubKey"]
            and candidate["registrationStatus"] == "Active"
        ):
            registration2Active = True
            continue

    if not registration1Active and registration2Active:
        context.to_register_SPO_public_key = context.ctl_params["registration1"][
            "spo-public-key"
        ]
        context.to_deregister_SPO_public_key = context.ctl_params["registration2"][
            "spo-public-key"
        ]
        context.new_registration = "registration1"
    else:
        context.to_register_SPO_public_key = context.ctl_params["registration2"][
            "spo-public-key"
        ]
        context.to_deregister_SPO_public_key = context.ctl_params["registration1"][
            "spo-public-key"
        ]
        context.new_registration = "registration2"
    logger.info(
        f"This time we will register {context.to_register_SPO_public_key} and "
        f"deregister {context.to_deregister_SPO_public_key}"
    )


@when("we register a validator to the bridge contract on Cardano")
def step_impl(context):
    context.just_registered_spo_public_key = bridge_api.registerSPO(
        context, context.new_registration
    )


@when("we register a temporary validator to the bridge contract on Cardano")
def step_impl(context):
    context.temp_registered_spo_public_key = bridge_api.registerSPO(
        context, "registration3"
    )


@when("we register a validator with low pledge to the bridge contract on Cardano")
def step_impl(context):
    context.low_pledge_invalid_spo_public_key = bridge_api.registerSPO(
        context, "registration4"
    )


@when("we de-register another validator from the bridge contract on Cardano")
def step_impl(context):
    bridge_api.deregisterSPO(context, context.to_deregister_SPO_public_key)


@when("we de-register the temporary validator from the bridge contract on Cardano")
def step_impl(context):
    bridge_api.deregisterSPO(
        context, context.ctl_params["registration3"]["spo-public-key"]
    )


@when("we de-register a validator with low pledge from the bridge contract on Cardano")
def step_impl(context):
    bridge_api.deregisterSPO(
        context, context.ctl_params["registration4"]["spo-public-key"]
    )


@when("we request the list of registrations from the mainchain contract")
def step_impl(context):
    utxos = cardano_cli.getAddrUTxOs(
        context.bridge_params["mc_bridge_contract_addr"],
        context.bridge_params["mainchain_network"],
    )
    context.mc_bridge_registrations = utxos
    assert type(utxos) == dict, "ERROR: registrations returned an unexpected type"


@when("we query db-sync for latest block")
def step_impl(context):
    try:
        dbhost = context.dbsync_params["db_host"]
        dbport = context.dbsync_params["db_port"]
        dbname = context.dbsync_params["db_name"]
        dbuser = context.dbsync_params["db_user"]
        dbpass = context.dbsync_pass
    except Exception as e:
        assert False, f"ERROR: {e}"
    try:
        psql_path = context.dbsync_params['psql_path']
        db_sync_block, err = bridge_api.run_command(f"PGPASSWORD={dbpass} {psql_path} \
                                                    -h {dbhost} -p {dbport} \
                                                    -d {dbname} -U {dbuser} \
                                                    -c \"select block_no from \
                                                    block where block_no is not \
                                                    null order by block_no desc \
                                                    limit 1 ;\" | \
                                                    grep -o '[ ].*.[0-9]'",
                                                    logs_enabled=False,
                                                    shell=True)
        db_sync_block = int(db_sync_block)
        context.db_sync_block = db_sync_block
    except Exception as e:
        assert False, f"ERROR: Could not query db sync: {e}"
    assert (
        type(db_sync_block) == int
    ), "ERROR: Db sync response for latest block is not an integer"


@when("we send 10 sidechain tokens from Cardano network to Sidechain address")
def step_impl(context):
    tx_id = bridge_api.burnSCTokens(
        context.trustless_ctl_cli,
        context.bridge_params["mc_sc_token_skey_file"],
        context.ctl_params["sidechainParameters"]["chainId"],
        context.ctl_params["sidechainParameters"]["genesisHash"],
        context.ctl_params["sidechainParameters"]["genesisUtxo"],
        context.ctl_params["sidechainParameters"]["genesisMint"],
        context.ctl_params["sidechainParameters"]["threshold"]["numerator"],
        context.ctl_params["sidechainParameters"]["threshold"]["denominator"],
        TOKENS_TO_SEND,
        context.sc_payment_addr,
    )

    burn_tx = BurnTx()
    burn_tx.tx_id = f"0x{tx_id}"
    burn_tx.value = hex(TOKENS_TO_SEND)
    burn_tx.recipient = context.sc_payment_addr

    if hasattr(context, "burn_txs") and context.burn_txs:
        logger.warn(f"Overriding context.burn_txs {context.burn_txs} with {burn_tx}")
    context.burn_txs = [burn_tx]

    bridge_api.waitForNextSCBlock(context)


@when("we lock 10 sidechain tokens on the sidechain contract")
def step_impl(context):
    context.bech32_destination_addr = bridge_api.lockSCToken(
        context.sidechain_cli,
        context.ethRPC,
        context.sc_payment_addr,
        context.sc_payment_key,
        context.mc_sc_token_addr,
        TOKENS_TO_SEND * MC_SC_TOKEN_RATIO,
    )


@when("number of sidechain validator candidates is equal to threshold")
def step_impl(context):
    assert True


@when("number of sidechain validator candidates is equal to threshold - 1")
def step_impl(context):
    assert True


@when("cardano SPO 1 retires")
def step_impl(context):
    assert True


###################### bridge_03_interaction.feature ###################


@when("we request the list of candidates")
def step_impl(context):
    try:
        context.candidates = eval(
            context.ethRPC.sidechain_getCandidates("latest").__str__()
        )
    except Exception as e:
        assert False, f"ERROR: Could not get list of sidechain candidates {e}"
    assert True


@when("we request the committee")
def step_impl(context):
    try:
        context.committee = eval(
            context.ethRPC.sidechain_getCommittee("latest").__str__()
        )
    except Exception as e:
        assert False, f"ERROR: Could not get latest sidechain committee: {e}"
    assert True


@when("we request the committee of previous epochs")
def step_impl(context):
    prev_committees = []
    try:
        for i in range(1, NO_OF_PREV_EPOCHS_TO_TEST + 1):
            try:
                prev_committee = eval(
                    context.ethRPC.sidechain_getCommittee(
                        context.sidechain_epoch - i
                    ).__str__()
                )
            except Exception as e:
                assert False, f"ERROR: {e}"
            assert (
                "committee" in prev_committee.keys()
            ), f"ERROR: No committee info available for epoch \
               {context.sidechain_epoch - i}"
            prev_committees.append(prev_committee)
        context.previous_committees_list = prev_committees
    except Exception as e:
        assert False, f"ERROR: Could not get previous sidechain committees: {e}"
    assert True


@when("we request the epoch signatures of those previous epochs")
def step_impl(context):
    prev_epochSignatures = []
    try:
        for i in range(1, NO_OF_PREV_EPOCHS_TO_TEST + 1):
            try:
                prev_epochSig = eval(
                    context.ethRPC.sidechain_getEpochSignatures(
                        context.sidechain_epoch - i
                    ).__str__()
                )
            except Exception as e:
                assert False, f"ERROR: {e}"
            prev_epochSignatures.append(prev_epochSig)
        context.previous_epoch_signatures_list = prev_epochSignatures
    except Exception as e:
        assert False, f"ERROR: Could not get previous epoch signatures {e}"
    assert True


###################### bridge_04_functionality.feature ###################


@when("we wait until best block becomes stable")
def step_impl(context):
    # Wait for block to become stable
    timeout = True
    for i in range(
        context.bridge_params["mc_stability_param"]
    ):  # 36 blocks to become stable
        info = context.ethRPC.sidechain_getStatus()
        mc_stable_block = info["mainchain"]["stableBlock"]["number"]
        context.sc_best_block = info["sidechain"]["bestBlock"]["number"]
        logger.debug(
            f"Waiting for last tx best block "
            f"{context.cardano_best_block_from_SC} to become stable, "
            f"current mc stable block: {mc_stable_block}"
        )
        if mc_stable_block >= context.cardano_best_block_from_SC:
            timeout = False
            break
        time.sleep(40)  # Giving a few extra seconds per block
    assert (
        not timeout
    ), f"TIMEOUT: Block stability not reached in given time. \
       {mc_stable_block} < {context.cardano_best_block_from_SC}"
    try:
        context.sc_best_block = int(context.sc_best_block, 16)
    except Exception as e:
        assert (
            False
        ), f"ERROR: best block not a hex string: {context.sc_best_block}\n{e}"


@when("we wait until the sidechain phase has changed to the next handover")
def step_impl(context):
    i = 0
    timeout = False
    while (
        context.sc_epoch != context.outgoing_tx_epoch
        or context.sc_epoch_phase != "handover"
    ):
        time.sleep(30)
        i = i + 1
        bridge_api.get_mc_status_from_sc(context)
        if (
            i >= 2 * (7 / 6 * context.bridge_params["sc_stability_param_k"]) + 2
        ):  # Assuming that slot=5sec, so k equivalent to minutes
            timeout = True
            break
    assert not timeout, "ERROR: Timeout: did not get to next epoch in time"
    bridge_api.waitForNextSCBlock(
        context
    )  # Wait until the first block after handover phase


@when("we wait until the sidechain epoch has changed")
def step_impl(context):
    i = 0
    timeout = False
    current_epoch = context.sc_epoch
    while context.sc_epoch != current_epoch + 1:
        time.sleep(30)
        i = i + 1
        bridge_api.get_mc_status_from_sc(context)
        if i >= 2 * 1.5 * context.bridge_params["sc_stability_param_k"]:
            timeout = True
            break
    assert not timeout, "ERROR: Timeout: did not get to next epoch in time"
    bridge_api.waitForNextSCBlock(
        context
    )  # Wait until the first block after new epoch\


@when("we wait until the committee handover has happened")
def step_impl(context):
    rootHashesToSubmitEmpty = False
    i = 0
    while not rootHashesToSubmitEmpty and i < 30:
        i += 1
        root_hashes = bridge_api.getSignaturesToUpload(context)
        if root_hashes == []:
            rootHashesToSubmitEmpty = True
            break
        for epoch_root_hash in root_hashes:
            assert (
                "epoch" in epoch_root_hash.keys()
            ), 'ERROR: key "epoch" not found in sidechain_getSignaturesToUpload return'
            assert (
                "rootHashes" in epoch_root_hash.keys()
            ), 'ERROR: key "rootHashes" not found in \
                sidechain_getSignaturesToUpload return'
            if epoch_root_hash["epoch"] == context.sc_epoch - 1:
                if epoch_root_hash["rootHashes"] == []:
                    rootHashesToSubmitEmpty = True
                    break
        time.sleep(10)
    assert (
        rootHashesToSubmitEmpty
    ), "ERROR: Timeout 300 seconds: Is the committee handover relay running?"


@when("we claim the sidechain tokens on mainchain")
def step_impl(context):
    context.claim_response, context.claim_error = bridge_api.claimSCTokenOnMainchain(
        context.trustless_ctl_cli,
        context.bridge_params["mc_sc_token_skey_file"],
        context.ctl_params["sidechainParameters"]["chainId"],
        context.ctl_params["sidechainParameters"]["genesisHash"],
        context.ctl_params["sidechainParameters"]["genesisUtxo"],
        context.ctl_params["sidechainParameters"]["genesisMint"],
        context.ctl_params["sidechainParameters"]["threshold"]["numerator"],
        context.ctl_params["sidechainParameters"]["threshold"]["denominator"],
        context.merkleProofBytes,
    )
    bridge_api.waitForNextMCBlock(context)


@when("we try to lock more sidechain tokens than sidechain account's balance")
def step_impl(context):
    sc_account_balance = context.ethRPC.eth_getBalance(
        context.sc_payment_addr, "latest"
    ).__str__()
    sc_account_balance = int(sc_account_balance, 16)
    overdraft = int(sc_account_balance / MC_SC_TOKEN_RATIO + 1) * MC_SC_TOKEN_RATIO
    try:
        bridge_api.lockSCToken(
            context.sidechain_cli,
            context.ethRPC,
            context.sc_payment_addr,
            context.sc_payment_key,
            context.mc_sc_token_addr,
            overdraft,
        )
        context.overdraft_is_possible = True
    except Exception as e:
        context.overdraft_is_possible = False
        assert True, f"ERROR: Could lock more than account's balance! {e}"


######################################################################
################################ THEN ################################
######################################################################

###################### bridge_01_setup.feature #######################


@then("we verify that its hash is the same on another node")
def step_impl(context):
    block_by_hash = context.ethRPC2.eth_getBlockByHash(context.latest_sc_evm_block_hash)
    assert context.latest_sc_evm_block_hash == block_by_hash["hash"]


@then("we verify that it is synced")
def step_impl(context):
    assert context.cardano_syncProgress == "100.00"


@then("all three match")
def step_impl(context):
    assert (
        abs(context.db_sync_block - context.cardano_block) < BEST_BLOCK_TOLERANCE
    ), f"ERROR: Latest block from dbsync does not match best block from Cardano, \
       {context.db_sync_block} != {context.cardano_block}"
    assert (
        abs(context.cardano_best_block_from_SC - context.cardano_block)
        < BEST_BLOCK_TOLERANCE
    ), f"ERROR: Latest block from sidechain does not match best block \
        from Cardano, {context.cardano_best_block_from_SC} != {context.cardano_block}"


###################### bridge_02_sidechain.feature ###################


@then("the mainchain public key 1 is found as active in the list of candidates")
def step_impl(context):
    registration_found_active = False
    for candidate in context.current_candidates:
        # Variable name to_deregister_SPO_public_key can be misleading.
        # It means after it is registered, it will be the one
        # that has to be deregistered next time.
        if (
            context.to_deregister_SPO_public_key in candidate["mainchainPubKey"]
            and "registrationStatus" in candidate.keys()
            and candidate["registrationStatus"] == "Active"
        ):
            registration_found_active = True
            break
    assert (
        registration_found_active
    ), f"ERROR: Registration not found in list of candidates as Active: \
       {context.to_deregister_SPO_public_key}"


@then("the mainchain public key 2 is NOT found in the list of candidates")
def step_impl(context):
    found_candidate = False
    for candidate in context.current_candidates:
        # Variable name to_register_SPO_public_key can be misleading.
        # It means after it is deregistered, it will be the one
        # that has to be registered next time.
        if context.to_register_SPO_public_key in candidate["mainchainPubKey"]:
            found_candidate = True
            break
    assert (
        not found_candidate
    ), f"ERROR: Registration found in list of candidates: \
       {context.to_register_SPO_public_key}"


@then("the validator is pending registration on the contract")
def step_impl(context):
    registration_found = False
    for candidate in context.current_candidates:
        # Verify that the registration is found and it is a new registration
        if (
            context.just_registered_spo_public_key in candidate["mainchainPubKey"]
            and "registrationStatus" in candidate.keys()
            and candidate["utxo"]["mainchainBlockNumber"]
            > context.last_registration_mc_block[context.just_registered_spo_public_key]
        ):
            registration_found = True
            assert (
                candidate["registrationStatus"] == "Pending"
            ), f"ERROR: Registration Status is not Pending, \
               {candidate['registrationStatus']}"
    assert registration_found, "ERROR: Registered validator not found at all"


@then("the other validator is pending deregistration on the contract")
def step_impl(context):
    # Determine if the registration is still Pending or not
    registration_found = False
    for candidate in context.current_candidates:
        if (
            context.just_deregistered_spo_public_key in candidate["mainchainPubKey"]
            and "upcomingChange" in candidate.keys()
            and "registrationStatus" in candidate.keys()
        ):
            registration_found = True
            assert (
                candidate["upcomingChange"]["newState"] == "Deregistered"
            ), f"ERROR: Registration upcoming change new state not Deregistered: \
               {candidate['upcomingChange']['newState']}"
            assert (
                candidate["registrationStatus"] == "PendingDeregistration"
            ), f"ERROR: Registration Status is not Pending Deregistration: \
               {candidate['registrationStatus']}"
    if context.deregistration_status == "Pending":
        assert (
            not registration_found
        ), "Error: A pending registration was not removed by deregistration"
    else:
        assert registration_found, "ERROR: Deregistered validator not found at all"


@then("the temporary validator is not registered on the contract")
def step_impl(context):
    registration_found = False
    for candidate in context.current_candidates:
        if context.temp_registered_spo_public_key in candidate["mainchainPubKey"]:
            registration_found = True
    assert (
        not registration_found
    ), "Error: A pending registration was not removed by deregistration"


@then("the low pledge validator is registered on the contract")
def step_impl(context):
    registration_found = False
    for candidate in context.current_candidates:
        if context.low_pledge_invalid_spo_public_key in candidate["mainchainPubKey"]:
            registration_found = True
            context.low_pledge_registration_status = candidate["registrationStatus"]
    assert registration_found, "ERROR: Low pledge validator not found registered at all"
    # The assertion of being invalid will be tested after the deregistration
    # to avoid deregistrations being prevented by failures


@then("the low pledge validator was registered as Invalid on the contract")
def step_impl(context):
    assert (
        context.low_pledge_registration_status == "Invalid"
    ), f"ERROR: Registration Status is not Invalid:\n \
            SPO Public key {context.low_pledge_invalid_spo_public_key} \
            Status: {context.low_pledge_registration_status}"


@then("the low pledge validator is not registered on the contract")
def step_impl(context):
    registration_found = False
    for candidate in context.current_candidates:
        if context.low_pledge_invalid_spo_public_key in candidate["mainchainPubKey"]:
            registration_found = True
    assert (
        not registration_found
    ), f"Error: A pending registration was not removed by deregistration: \
       {context.low_pledge_invalid_spo_public_key}"


@then("Sidechain network is awaiting for minimum number of validators")
def step_impl(context):
    assert True


@then("Sidechain network is producing blocks")
def step_impl(context):
    assert True


###################### bridge_03_interaction.feature ###################


@then("the committee members are a subset of the candidates")
def step_impl(context):
    candidate_sc_pubKey_set = set()
    for candidate in context.candidates:
        candidate_sc_pubKey_set.add(candidate["sidechainPubKey"])
    for committee_member in context.committee["committee"]:
        assert (
            committee_member["sidechainPubKey"] in candidate_sc_pubKey_set
        ), "ERROR: Committee member not found in candidate list"


@then("Cardano block matches mainchain block from sidechain")
def step_impl(context):
    assert (
        abs(context.cardano_block - context.cardano_best_block_from_SC)
        <= BEST_BLOCK_TOLERANCE
    ), f"ERROR: Sidechain does not have latest mainchain block, \
        {context.cardano_best_block_from_SC} != {context.cardano_block}"


@then("Cardano tip matches mainchain tip from sidechain")
def step_impl(context):
    assert (
        abs(context.cardano_tip - context.cardano_tip_from_SC) <= LATEST_TIP_TOLERANCE
    ), f"ERROR: Sidechain does not have latest mainchain tip, \
       {context.cardano_tip_from_SC} != {context.cardano_tip}"


@then("Cardano epoch matches mainchain epoch from sidechain")
def step_impl(context):
    assert (
        context.cardano_epoch == context.cardano_epoch_from_SC
    ), f"ERROR: Sidechain does not have latest mainchain epoch, \
       {context.cardano_epoch_from_SC} != {context.cardano_epoch}"


@then("all honest committee members have signed handover and transactions")
def step_impl(context):
    # Get pubKey of test SPOs (dishonest)
    spo1_sc_pub_key = (
        "0x"
        + bridge_api.getECDSAPublicKey(
            context.sidechain_cli,
            context.ctl_params["registration1"]["sidechain-signing-key"],
        )["public"]
    )
    spo2_sc_pub_key = (
        "0x"
        + bridge_api.getECDSAPublicKey(
            context.sidechain_cli,
            context.ctl_params["registration2"]["sidechain-signing-key"],
        )["public"]
    )
    spo3_sc_pub_key = (
        "0x"
        + bridge_api.getECDSAPublicKey(
            context.sidechain_cli,
            context.ctl_params["registration3"]["sidechain-signing-key"],
        )["public"]
    )
    spo4_sc_pub_key = (
        "0x"
        + bridge_api.getECDSAPublicKey(
            context.sidechain_cli,
            context.ctl_params["registration4"]["sidechain-signing-key"],
        )["public"]
    )
    dishonest_spos = [
        spo1_sc_pub_key,
        spo2_sc_pub_key,
        spo3_sc_pub_key,
        spo4_sc_pub_key,
    ]

    for i in range(0, NO_OF_PREV_EPOCHS_TO_TEST):
        committee_pubKey_list = []
        handover_signers_pubKey_list = []
        txs_signers_pubKey_list = []
        for member in context.previous_committees_list[i]["committee"]:
            # Remove the test validators added by this testframe
            if member["sidechainPubKey"] in dishonest_spos:
                continue
            committee_pubKey_list.append(member["sidechainPubKey"])
        for member in context.previous_epoch_signatures_list[i]["committeeHandover"][
            "signatures"
        ]:
            handover_signers_pubKey_list.append(member["committeeMember"])
        committee_pubKey_list.sort()
        handover_signers_pubKey_list.sort()
        assert (
            committee_pubKey_list == handover_signers_pubKey_list
        ), f"ERROR: Not all committee members signed handover for epoch \
            {context.sidechain_epoch - i - 1}\n \
            SPO missing signature: \
            {set(committee_pubKey_list) - set(handover_signers_pubKey_list)}\n \
            Dishonest SPO with signature: \
            {set(handover_signers_pubKey_list) - set(committee_pubKey_list)}\n"
        # Only if there are transactions, verify that all
        # honest committee members signed them
        if (
            "outgoingTransactions" in context.previous_epoch_signatures_list[i].keys()
            and context.previous_epoch_signatures_list[i]["outgoingTransactions"] != []
        ):
            for member in context.previous_epoch_signatures_list[i][
                "outgoingTransactions"
            ][0]["signatures"]:
                txs_signers_pubKey_list.append(member["committeeMember"])
            txs_signers_pubKey_list.sort()
            assert (
                committee_pubKey_list == txs_signers_pubKey_list
            ), f"ERROR: Not all committee members signed transactions for epoch \
                {context.sidechain_epoch - i - 1}\n \
                SPO missing signature: \
                {set(committee_pubKey_list) - set(txs_signers_pubKey_list)}\n \
                Dishonest SPO with signature:  \
                {set(txs_signers_pubKey_list) - set(committee_pubKey_list)}\n"


###################### bridge_04_functionality.feature ###################


@then("Sidechain address balance increases by 10")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)
    sc_evm_new_balance = context.ethRPC.eth_getBalance(
        context.receiving_sc_evm_addr, "latest"
    ).__str__()
    assert utils.is_hex(sc_evm_new_balance), "ERROR: Balance returned not a hex number"
    sc_evm_new_balance = int(sc_evm_new_balance, 16)
    assert math.isclose(
        sc_evm_new_balance / MC_SC_TOKEN_RATIO,
        context.receiving_sc_evm_balance / MC_SC_TOKEN_RATIO + TOKENS_TO_SEND,
        abs_tol=0.00001,
    ), f"ERROR: New balance does not reflect the transfer from MC to SC: \n \
            {sc_evm_new_balance/MC_SC_TOKEN_RATIO} != \
            {context.receiving_sc_evm_balance/MC_SC_TOKEN_RATIO + TOKENS_TO_SEND}"


@then("the cardano address balance of sidechain token with policy ID equals to x + 10")
def step_impl(context):
    bridge_api.waitForNextMCBlock(context)
    final_sc_token_balance_on_mc = bridge_api.getSCTokenBalanceOnMC(
        context, context.mc_sc_token_addr
    )
    assert (
        final_sc_token_balance_on_mc
        == context.receiving_cardano_addr_sc_token_balance + TOKENS_TO_SEND
    ), f"ERROR: Balance doesn't match: {final_sc_token_balance_on_mc} != \
        {context.receiving_cardano_addr_sc_token_balance} + TOKENS_TO_SEND"


@then("the sidechain token transaction is identified as pending")
def step_impl(context):
    response, err = bridge_api.getPendingTxs(
        context.sidechain_cli, context.bridge_params["sidechain_node1"]
    )
    if err:
        assert False, f"Unexpected error while getting pending txs: {err}"

    assert (
        hasattr(context, "burn_txs") and context.burn_txs
    ), "context.burn_txs list is empty"

    for burn_tx in context.burn_txs:
        matching_txs = [tx for tx in response.pending if tx.txId == burn_tx.tx_id]
        assert (
            len(matching_txs) == 1
        ), f"Expected exactly one tx with hash {burn_tx.tx_id}, but was: {matching_txs}"
        assert (
            hex(matching_txs[0].value) == burn_tx.value
        ), f"Tx value doesn't match {hex(matching_txs[0].value)} != {burn_tx.value}"
        assert (
            matching_txs[0].recipient.lower() == burn_tx.recipient.lower()
        ), f"Tx recipient doesn't match {matching_txs[0].recipient} != \
            {burn_tx.recipient}"


@then("the transaction appears on the sidechain outgoing transactions")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)
    if context.sc_epoch_phase == "regular":
        epoch = context.sc_epoch
    else:
        epoch = context.sc_epoch + 1
    context.outgoing_tx_epoch = epoch
    try:
        outgoing_txs = eval(
            context.ethRPC.sidechain_getOutgoingTransactions(epoch).__str__()
        )
    except Exception as e:
        assert False, f"ERROR: {e}"
    found_tx = False
    for tx in outgoing_txs["transactions"]:
        if tx["recipient"] in "0x" + context.bech32_destination_addr and tx[
            "value"
        ] == hex(TOKENS_TO_SEND):
            context.outgoing_tx_index = tx["txIndex"]
            found_tx = True
            # TODO: Verify txHash
            break
    assert found_tx, "ERROR: Lock tx not identified as outgoing"


@then("the merkle root hash of the transaction is obtained")
def step_impl(context):
    try:
        outgoing_TxMerkleProof = eval(
            context.ethRPC.sidechain_getOutgoingTxMerkleProof(
                context.outgoing_tx_epoch, context.outgoing_tx_index
            ).__str__()
        )
    except Exception as e:
        assert False, f"ERROR: {e}"
    try:
        signatures = eval(
            context.ethRPC.sidechain_getEpochSignatures(
                context.outgoing_tx_epoch
            ).__str__()
        )
    except Exception as e:
        assert False, f"ERROR: {e}"

    assert (
        "proof" in outgoing_TxMerkleProof.keys()
    ), 'ERROR: key "proof" not found in sidechain_getOutgoingTxMerkleProof return'
    assert (
        "bytes" in outgoing_TxMerkleProof["proof"].keys()
    ), "ERROR: key \"bytes\" not found in sidechain_getOutgoingTxMerkleProof['proof'] \
        return"
    assert (
        "info" in outgoing_TxMerkleProof["proof"].keys()
    ), "ERROR: key \"info\" not found in sidechain_getOutgoingTxMerkleProof['proof'] \
        return"
    assert (
        "merkleRootHash" in outgoing_TxMerkleProof["proof"]["info"].keys()
    ), "ERROR: key \"merkleRootHash\" not found in outgoing_TxMerkleProof['proof']\
        ['info'] \return"
    assert (
        "outgoingTransactions" in signatures.keys()
    ), 'ERROR: key "outgoingTransactions" not found in sidechain_getEpochSignatures \
        return'
    assert (
        type(signatures["outgoingTransactions"]) == list
    ), "ERROR: Outgoing Txs not a list"
    merkleProofMatched = False
    merkleProofListFromSignatures = []
    for outgoingTx in signatures["outgoingTransactions"]:
        merkleProofListFromSignatures.append(outgoingTx["merkleRootHash"])
        if (
            outgoing_TxMerkleProof["proof"]["info"]["merkleRootHash"]
            == outgoingTx["merkleRootHash"]
        ):
            merkleProofMatched = True
            context.merkleProofBytes = outgoing_TxMerkleProof["proof"]["bytes"][
                2:
            ]  # Drop the 0x
            break
    assert (
        merkleProofMatched
    ), f"ERROR: MerkleProof from Tx not found within signatures, \n \
          From Tx: {outgoing_TxMerkleProof['proof']['info']['merkleRootHash']} \n \
          From signatures: {merkleProofListFromSignatures}"


@then("the claim should be succesful")
def step_impl(context):
    try:
        ctl_response_dict = eval(context.claim_response)
    except Exception as e:
        assert (
            False
        ), f"ERROR: Could not convert CTL response to dictionary: \
            {e}\n{context.claim_response}"
    assert (
        ctl_response_dict["endpoint"] == "ClaimAct"
    ), f"ERROR: Could not claim sidechain tokens: {context.claim_response}"


@then("the claim should fail")
def step_impl(context):
    assert (
        "Error: FUELMintingPolicy.mintFUEL" in context.claim_error
    ), f"ERROR: Could claim sidechain tokens second time: \
        {context.claim_response}\n{context.claim_error}"


@then("the lock operation fails")
def step_impl(context):
    assert (
        not context.overdraft_is_possible
    ), "ERROR: Lock operation with more than balance did NOT fail!!!"


@then("the transaction appears in the list of incoming transactions")
def step_impl(context):
    tx_id = context.burn_txs[0].tx_id[2:]  # without 0x
    try:
        incoming_txs, err = bridge_api.getIncomingTxs(
            context.sidechain_cli,
            context.bridge_params["sidechain_node1"],
            context.sc_best_block - 50,
        )
    except Exception as e:
        assert (
            False
        ), f"ERROR: Could not get incoming transactions: {incoming_txs}\n{e}\n{err}"
    recipient = context.sc_payment_addr[2:].lower()
    assert (
        f"* hash: {tx_id}\n  * recipient: {recipient}\n  * value: \
            {TOKENS_TO_SEND*MC_SC_TOKEN_RATIO}\n  * status: Success"
        in incoming_txs
    ), f"ERROR: Could not find: transaction {tx_id},\n \
         recipient {recipient},\n \
         value {TOKENS_TO_SEND*MC_SC_TOKEN_RATIO},\n \
         in incoming txs from block {context.sc_best_block}:\n \
         {incoming_txs}"
