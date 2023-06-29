# -- FILE: features/steps/bridge_steps.py
from behave import given, when, then, use_fixture
from behave import __main__ as runner_with_options
import os
from os.path import exists
import sys
import argparse
import json
import time
import random
from sqlalchemy import select
from sqlalchemy.sql import func

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
grandparent = os.path.dirname(parent)
tests_folder_path = os.path.dirname(grandparent)
root_path = os.path.dirname(tests_folder_path)
sys.path.append(root_path)

from utils import utils, cardano_cli, sendTokens
import utils.log_wrapper as logger
import soak_api
import bridge_api
from fixtures import get_db_session
from models.db.transaction import OutgoingTransaction
from models.sc_evm.burn_tx import BurnTx

NUMBER_OF_ACCOUNTS = 10
MC_SC_TOKEN_RATIO = pow(10, 9)
TX_SKIPPED_EMPTY_ACC = 300  # custom error code
BURN_TX_QUEUED_TIMEOUT = 600


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
            "-s",
            "--format=pretty",
            "--include",
            "soak",
            #   '--include', 'soak_01', # Enable one at a time or disable all
            #   '--include', 'soak_02'
        ]
    )
    sys.exit(result)


######################################################################
############################### GIVEN ################################
######################################################################

##########################soak_01_active##############################


@given("we have a funded mainchain account with at least 505 tADA")
def step_impl(context):
    utxos = cardano_cli.getAddrUTxOs(
        context.mc_sc_token_addr, context.bridge_params["mainchain_network"]
    )
    assert (
        utxos is not False
    ), f"ERROR: Could not get UTxOs of address {context.mc_sc_token_addr}"
    tokensDict = cardano_cli.getTokenListFromTxHash(utxos)
    # 1.444443 for native token transfer + network fees
    assert tokensDict["ADA"] > 505 * pow(
        10, 6
    ), f"ERROR: Insufficient balance ({tokensDict['ADA']} lovelace) on address \
        {context.mc_sc_token_addr}"
    context.tokensDict = tokensDict


@given("we have a funded sidechain account with at least 100,000,000 sidechain tokens")
def step_impl(context):
    sending_sc_evm_balance = context.ethRPC.eth_getBalance(
        context.sc_payment_addr, "latest"
    ).__str__()
    assert utils.is_hex(sending_sc_evm_balance), "ERROR: Balance return unknown format"
    assert (
        int(sending_sc_evm_balance, 16) >= 100000000 * 10**18
    ), f"ERROR: Balance less than 100M sidechain tokens in gwei: \
        {int(sending_sc_evm_balance, 16)}"


##########################soak_02_passive##############################


@given("we have 10 mainchain addresses")
def step_impl(context):
    context.mainchain_accounts = []
    context.mainchain_account_key_files = []
    context.mc_accounts_dict = {}

    for file in os.listdir(context.bridge_params["generated_accounts_folder"]):
        if file.endswith(".addr"):
            mc_address = bridge_api.read_file(
                os.path.join(context.bridge_params["generated_accounts_folder"], file)
            )
            context.mainchain_accounts.append(mc_address)
            skey_file = file[:-4] + "skey"
            skey_file = os.path.join(
                context.bridge_params["generated_accounts_folder"], skey_file
            )
            context.mainchain_account_key_files.append(skey_file)
            try:
                bech32_destination_addr, err = bridge_api.run_command(
                    ["bash", "-c", f"bech32 <<< {mc_address}"]
                )
                bech32_destination_addr = bech32_destination_addr.strip()
            except Exception as e:
                assert False, f"ERROR: Could not get bech32 of {mc_address}: {err}\n{e}"
            context.mc_accounts_dict[bech32_destination_addr] = {
                "addr": mc_address,
                "skey_file": skey_file,
            }
    assert (
        len(context.mainchain_accounts) == NUMBER_OF_ACCOUNTS
    ), "ERROR: Some MC accounts are missing"


@given("we have 10 sidechain addresses")
def step_impl(context):
    try:
        with open(
            os.path.join(
                context.bridge_params["generated_accounts_folder"],
                "sidechain_accounts.json",
            ),
            "r",
        ) as file:
            sidechain_accounts_list = json.load(file)
    except Exception as e:
        assert False, f"ERROR: Could not read sidechain_accounts.json: {e}"
    assert (
        type(sidechain_accounts_list) == list
    ), "ERROR: Could not load a list of accounts"
    for account in sidechain_accounts_list:
        assert "addr" in account.keys(), "ERROR: Account does not contain key <addr>"
        assert "skey" in account.keys(), "ERROR: Account does not contain key <skey>"
    context.sidechain_accounts = sidechain_accounts_list
    assert (
        len(context.sidechain_accounts) == NUMBER_OF_ACCOUNTS
    ), "ERROR: Some SC accounts are missing"


######################################################################
################################ WHEN ################################
######################################################################

##########################soak_01_active##############################


@when("we generate 10 sidechain accounts")
def step_impl(context):
    sidechain_accounts_list = []
    for i in range(NUMBER_OF_ACCOUNTS):
        new_keys = utils.generate_keys("", True)
        sidechain_accounts_list.append(new_keys)
    context.sidechain_accounts = sidechain_accounts_list
    with open(
        os.path.join(
            context.bridge_params["generated_accounts_folder"],
            "sidechain_accounts.json",
        ),
        "w",
    ) as file:
        json.dump(sidechain_accounts_list, file, indent=4, sort_keys=True)
    assert True


@when("we fund those 10 sidechain accounts with 10M sidechain tokens each")
def step_impl(context):
    context.sc_payment_addr = context.w3.toChecksumAddress(context.sc_payment_addr)
    for account in context.sidechain_accounts:
        fund_account = utils.sendEip1559Tx(
            context.w3,
            context.sc_payment_addr,
            context.sc_payment_key,
            account["addr"],
            10 * pow(10, 6) * pow(10, 18),
            context.ctl_params["sidechainParameters"]["chainId"],
            silent=True,
            wait=True,
            nonce=None,
        )
        assert fund_account, "ERROR: Could not fund account."
        account_balance = context.ethRPC.eth_getBalance(
            account["addr"], "latest"
        ).__str__()
        assert int(account_balance, 16) == 10 * pow(10, 6) * pow(
            10, 18
        ), f"ERROR: Balance not 10M sidechain tokens: {int(account_balance, 16)}"


@when("we generate 10 mainchain accounts")
def step_impl(context):
    # First clear the folder from old accounts
    for file in os.listdir("generated_accounts"):
        if file.startswith("mc_account"):
            os.remove(os.path.join("generated_accounts", file))
    context.mainchain_accounts = []
    for i in range(NUMBER_OF_ACCOUNTS):
        cardano_cli.generatePaymentKeyPair()
        cardano_cli.generatePaymentAddress(context.bridge_params["mainchain_network"])
        assert exists("payment.addr"), "ERROR: Mainchain payment address not generated"
        assert exists("payment.skey"), "ERROR: Mainchain payment skey not generated"
        assert exists("payment.vkey"), "ERROR: Mainchain payment vkey not generated"
        context.mainchain_accounts.append(bridge_api.read_file("payment.addr"))
        os.rename(
            "payment.addr", os.path.join("generated_accounts", f"mc_account{i+1}.addr")
        )
        os.rename(
            "payment.skey", os.path.join("generated_accounts", f"mc_account{i+1}.skey")
        )
        os.rename(
            "payment.vkey", os.path.join("generated_accounts", f"mc_account{i+1}.vkey")
        )


@when("we fund those 10 mainchain accounts with 50 tADA each")
def step_impl(context):
    for file in os.listdir("generated_accounts"):
        if file.endswith(".addr"):
            file_read = open(os.path.join("generated_accounts", file), "r")
            mc_addr = file_read.read().strip()
            sendTokens.main(
                context.mc_sc_token_addr,
                context.bridge_params["mc_sc_token_skey_file"],
                mc_addr,
                50 * 10**6,
                [],
                [],
                network=context.bridge_params["mainchain_network"],
                era=context.bridge_params["mainchain_era"],
            )
            bridge_api.waitForNextMCBlock(context)
            bridge_api.waitForNextMCBlock(context)
            balance, keys = cardano_cli.getLovelaceBalance(
                mc_addr, network=context.bridge_params["mainchain_network"]
            )
            assert balance >= 50 * 10**6


@when("we send 10 random sidechain token amounts between the 10 sidechain accounts")
def step_impl(context):
    # Getting the balance initially before we start sending txs
    sc_balance_list, total_initial_balance = soak_api.getSCTokenBalanceList(
        context, NUMBER_OF_ACCOUNTS
    )
    for i in range(NUMBER_OF_ACCOUNTS):
        if sc_balance_list[i] == 0:
            logger.info(
                f"Account {context.sidechain_accounts[i]['addr']} is empty. Skipping."
            )
            continue
        random_amount = 0
        while random_amount == 0:
            random_amount = int(
                random.random() * sc_balance_list[i]
            )  # Get a random number between 0 and balance of account
        random_sc_account = random.choice(context.sidechain_accounts)
        logger.info(
            f"Send {random_amount} from {context.sidechain_accounts[i]['addr']} to \
                {random_sc_account['addr']}"
        )
        response = utils.sendEip1559Tx(
            context.w3,
            context.sidechain_accounts[i]["addr"],
            context.sidechain_accounts[i]["skey"],
            random_sc_account["addr"],
            random_amount,
            context.ctl_params["sidechainParameters"]["chainId"],
            silent=True,
            wait=True,
        )
        logger.debug(response)
        if not response:
            assert False, "ERROR: Could not send sidechain transaction"
        bridge_api.waitForNextSCBlock(context)
    sc_balance_list, total_final_balance = soak_api.getSCTokenBalanceList(
        context, NUMBER_OF_ACCOUNTS
    )
    context.initial_sc_balance = total_initial_balance
    context.final_sc_balance = total_final_balance


@when(
    "we send a random amount of sidechain tokens from each sidechain account to \
    a random one of the 10 mainchain accounts"
)
def step_impl(context):
    # Getting the balance initially before we start sending txs
    # Not necessary if previous step is <we send 10 random amounts
    # between the 10 sidechain accounts>
    sc_balance_list, context.initial_sc_balance = soak_api.getSCTokenBalanceList(
        context, NUMBER_OF_ACCOUNTS
    )
    total_amount_locked = 0
    context.db_outgoing_txs = []
    session = use_fixture(get_db_session, context)
    for i in range(NUMBER_OF_ACCOUNTS):
        if sc_balance_list[i] == 0:
            logger.info(
                f"Account {context.sidechain_accounts[i]['addr']} is empty. Skipping."
            )
            continue
        random_amount = 0
        while random_amount == 0:
            random_amount = int(
                random.random() * sc_balance_list[i]
            )  # Get a random number between 0 and Sidechain tokens balance
        # Ensure it is a multiple of MC_SC_TOKEN_RATIO
        random_amount = int(random_amount / MC_SC_TOKEN_RATIO) * MC_SC_TOKEN_RATIO

        random_mc_account = random.choice(context.mainchain_accounts)
        total_amount_locked += random_amount

        logger.info(
            f"Lock {random_amount} from {context.sidechain_accounts[i]['addr']} to \
                {random_mc_account}"
        )

        bech32_destination_addr = bridge_api.lockSCToken(
            context.sidechain_cli,
            context.ethRPC,
            context.sidechain_accounts[i]["addr"],
            context.sidechain_accounts[i]["skey"],
            random_mc_account,
            random_amount,
        )

        # calculate outgoing tx epoch
        sc_status_after_lock = context.ethRPC.sidechain_getStatus()["sidechain"]
        outgoing_tx_epoch = (
            sc_status_after_lock["epoch"]
            if sc_status_after_lock["epochPhase"] == "regular"
            else sc_status_after_lock["epoch"] + 1
        )

        # prepare tx object to be added to database
        outgoing_tx_db = OutgoingTransaction(
            sender=context.sidechain_accounts[i]["addr"],
            recipient=random_mc_account,
            recipient_bech32=f"0x{bech32_destination_addr}",
            value=str(random_amount),
            epoch=outgoing_tx_epoch,
            lock_timestamp=func.now(),
            skey_file_path=context.mc_accounts_dict[bech32_destination_addr][
                "skey_file"
            ],
        )

        logger.debug(f"Outgoing tx created (tokens locked): {outgoing_tx_db}")

        # add tx to database
        session.add(outgoing_tx_db)
        session.commit()
        context.db_outgoing_txs.append(outgoing_tx_db)

    final_balance = 0
    for account in context.sidechain_accounts:
        final_balance += int(
            context.ethRPC.eth_getBalance(account["addr"], "latest").__str__(), 16
        )
    context.total_tokens_locked = total_amount_locked
    context.total_sc_balance = final_balance

    assert True


@when("we claim the sidechain tokens of all lock txs on mainchain")
def step_impl(context):
    context.claim_responses = []
    context.claim_errors = []

    session = use_fixture(get_db_session, context)

    for out_tx in context.db_outgoing_txs:
        stmt = select(OutgoingTransaction).where(OutgoingTransaction.id == out_tx.id)
        current_tx = session.scalars(stmt).one()
        current_tx.claim_start_timestamp = func.now()
        session.commit()

        # claim tx
        claim_response, claim_error = bridge_api.claimSCTokenOnMainchain(
            context.sidechain_cli,
            context.bridge_params["sidechain_node1"],
            context.mc_accounts_dict[current_tx.recipient_bech32[2:]]["skey_file"],
            current_tx.merkle_proof,
        )

        context.claim_responses.append(claim_response)
        context.claim_errors.append(claim_error)

        # update claim result and end-timestamp in database
        try:
            ctl_response_dict = eval(claim_response)
            if ctl_response_dict["endpoint"] == "ClaimAct":
                current_tx.is_claimed = True
        except Exception as e:
            logger.error(
                f"ERROR: Could not convert CTL response to dictionary: \
                {e}\n{claim_response}"
            )
        finally:
            current_tx.claim_end_timestamp = func.now()
            session.commit()
            logger.debug(
                f"Updated claim_start, claim_end and is_claimed at: {current_tx}"
            )


##########################soak_02_passive##############################


@when("we send 10 random sidechain token amounts between the 10 mainchain accounts")
def step_impl(context):
    (
        context.mainchain_account_balances,
        context.initial_mc_balance,
        initial_ada_balance,
    ) = soak_api.getSCTokenBalanceListOnMC(context, NUMBER_OF_ACCOUNTS)

    for i in range(NUMBER_OF_ACCOUNTS):
        random_amount = 0
        if context.mainchain_account_balances[i] == 0:
            logger.info(f"Account {context.mainchain_accounts[i]} is empty. Skipping.")
            continue
        while random_amount == 0:
            random_amount = int(
                random.random() * context.mainchain_account_balances[i]
            )  # Get a number less than the account's balance
        random_mc_account = random.choice(context.mainchain_accounts)
        logger.info(
            f"Send {random_amount} from {context.mainchain_accounts[i]} to \
            {random_mc_account}"
        )
        sendTokens.main(
            context.mainchain_accounts[i],
            context.mainchain_account_key_files[i],
            random_mc_account,
            2 * 10**6,
            [context.bridge_params["mc_sc_token_policy_id"]],
            [random_amount],
            network=context.bridge_params["mainchain_network"],
            era=context.bridge_params["mainchain_era"],
        )


@when(
    "we send a random amount of sidechain tokens from each mainchain account to \
    a random one of the 10 sidechain accounts"
)
def step_impl(context):
    (
        context.mainchain_account_balances,
        context.initial_mc_balance,
        initial_ada_balance,
    ) = soak_api.getSCTokenBalanceListOnMC(context, NUMBER_OF_ACCOUNTS)
    sc_balance_list, total_initial_sc_balance = soak_api.getSCTokenBalanceList(
        context, NUMBER_OF_ACCOUNTS
    )

    if hasattr(context, "burn_txs") and context.burn_txs:
        logger.warn(
            f"Overriding context.burn_txs {context.burn_txs} with an empty list"
        )
    context.burn_txs = []
    for i in range(NUMBER_OF_ACCOUNTS):
        burn_tx = BurnTx()
        random_sc_account = random.choice(context.sidechain_accounts)
        burn_tx.recipient = random_sc_account["addr"]
        if context.mainchain_account_balances[i] == 0:
            logger.warn(f"Account {context.mainchain_accounts[i]} is empty. Skipping.")
            continue
        random_amount = 0
        while random_amount == 0:
            random_amount = int(
                random.random() * context.mainchain_account_balances[i]
            )  # Get a number less than the account's balance
        burn_tx.value = hex(random_amount)
        logger.info(
            f"Burn {random_amount} from {context.mainchain_accounts[i]} to \
            {random_sc_account['addr']}"
        )
        tx_id = bridge_api.burnSCTokens(
            context.sidechain_cli,
            context.bridge_params["sidechain_node1"],
            context.mainchain_account_key_files[i],
            random_amount,
            random_sc_account["addr"],
            context.ctl_params["sidechainParameters"]["genesisMint"],
        )
        burn_tx.tx_id = f"0x{tx_id}"
        context.burn_txs.append(burn_tx)

    # allow chain follower to see new txs
    bridge_api.waitForNextSCBlock(context)


@when("we wait until sidechain token transactions are no longer queued")
def step_when(context):
    assert (
        hasattr(context, "burn_txs") and context.burn_txs
    ), "ERROR: context.burn_txs list is empty"

    current_timestamp = int(time.time())
    timeout = current_timestamp + BURN_TX_QUEUED_TIMEOUT

    while True:
        response, err = bridge_api.getPendingTxs(
            context.sidechain_cli, context.bridge_params["sidechain_node1"]
        )

        logger.debug(f"Waiting for queued txs: {response.queued}")

        if err:
            msg = "Unknown error while waiting for queued txs"
            logger.error(f"{msg}, err: {err}")
            raise Exception(f"{msg}, err: {err}")

        if current_timestamp > timeout:
            msg = "Timeout while waiting for queued txs"
            logger.error(f"{msg}, response: {response}")
            raise TimeoutError(f"{msg}, response: {response}")

        if not response.queued:
            return  # no queued txs, exit

        has_queued_txs = False
        for burn_tx in context.burn_txs:
            logger.debug(f"Checking if tx {burn_tx.tx_id} is queued")
            queued_tx = [tx for tx in response.queued if tx.txId == burn_tx.tx_id]
            if queued_tx:
                has_queued_txs = True
                logger.debug(f"Transaction is still queued {burn_tx.tx_id}")
                break

        if has_queued_txs:
            time.sleep(10)
            current_timestamp = int(time.time())
        else:
            break


######################################################################
################################ THEN ################################
######################################################################

###################### soak_01_active.feature ########################


@then("the initial sum of sidechain tokens is equal to the final sum on the sidechain")
def step_impl(context):
    assert (
        context.initial_sc_balance == context.final_sc_balance
    ), f"ERROR: Initial balance of sidechain tokens of all accounts not equal \
        to the final balance on sidechain:\n \
        {context.initial_sc_balance} != {context.final_sc_balance}"


@then(
    "the total balance of the sidechain amount is reduced by the sum of tokens locked"
)
def step_impl(context):
    assert (
        context.total_sc_balance
        == context.initial_sc_balance - context.total_tokens_locked
    ), f"ERROR: Total sidechain balance is not equal to \
        initial balnce - total locked amount:\n \
        {context.total_sc_balance} != {context.initial_sc_balance} \
        - {context.total_tokens_locked}"


@then("the transactions appear on the sidechain outgoing transactions")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)

    if context.sc_epoch_phase == "regular":
        epoch = context.sc_epoch
    else:
        epoch = context.sc_epoch + 1
    context.outgoing_tx_epoch = epoch

    epochs = {tx.epoch for tx in context.db_outgoing_txs}
    session = use_fixture(get_db_session, context)
    for epoch in epochs:
        try:
            outgoing_txs = eval(
                context.ethRPC.sidechain_getOutgoingTransactions(epoch).__str__()
            )
        except Exception as e:
            assert False, f"ERROR: {e}"

        assert all(
            "recipient" in outgoing_tx.keys()
            for outgoing_tx in outgoing_txs["transactions"]
        ), f'ERROR: Key "recipient" was not found in \
            sidechain_getOutgoingTransactions({epoch})'

        assert all(
            "value" in outgoing_tx.keys()
            for outgoing_tx in outgoing_txs["transactions"]
        ), f'ERROR: Key "value" was not found in \
            sidechain_getOutgoingTransactions({epoch})'

        for db_tx in context.db_outgoing_txs:
            stmt = select(OutgoingTransaction).where(OutgoingTransaction.id == db_tx.id)
            current_tx = session.scalars(stmt).one()
            found_tx = False
            for outgoing_tx in outgoing_txs["transactions"]:
                if outgoing_tx["recipient"] == current_tx.recipient_bech32 and int(
                    outgoing_tx["value"], 0
                ) * MC_SC_TOKEN_RATIO == int(current_tx.value):
                    current_tx.tx_index = outgoing_tx["txIndex"]
                    found_tx = True
                    break
            assert (
                found_tx
            ), f"ERROR: Locked tx {db_tx} was not found at outgoing \
                {outgoing_txs}, epoch: {current_tx.epoch}"
            session.commit()
            logger.debug(f"Updated tx_index at: {current_tx}")


@then("all the claims should be succesful")
def step_impl(context):
    for i in range(NUMBER_OF_ACCOUNTS):
        if context.claim_responses[i] == TX_SKIPPED_EMPTY_ACC:
            continue
        try:
            ctl_response_dict = eval(context.claim_responses[i])
        except Exception as e:
            assert (
                False
            ), f"ERROR: Could not convert CTL response to dictionary: \
                {e}\n{context.claim_responses[i]}\n{context.claim_errors[i]}"
        assert (
            ctl_response_dict["endpoint"] == "ClaimAct"
        ), f"ERROR: Could not claim sidechain tokens: \
            {context.claim_responses[i]}\n{context.claim_errors[i]}"
    bridge_api.waitForNextMCBlock(context)


@then("the sum of the sidechain and mainchain accounts is 100M")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)
    bridge_api.waitForNextMCBlock(context)

    _, sc_token_balance = soak_api.getSCTokenBalanceList(context, NUMBER_OF_ACCOUNTS)
    _, sc_token_balance_on_mc, _ = soak_api.getSCTokenBalanceListOnMC(
        context, NUMBER_OF_ACCOUNTS
    )

    context.sidechain_balance = sc_token_balance
    context.mainchain_balance = sc_token_balance_on_mc * MC_SC_TOKEN_RATIO
    context.total_balance = context.sidechain_balance + context.mainchain_balance
    assert (
        context.total_balance == context.total_initial_balance
    ), f"ERROR: Current total balance not equal to the initial, \
        {context.total_balance} != {context.total_initial_balance}"


###################### soak_02_passive.feature #######################


@then("the initial sum of sidechain tokens is equal to the final sum on the mainchain")
def step_impl(context):
    bridge_api.waitForNextMCBlock(context)

    (
        context.mainchain_account_balances,
        context.final_mc_balance,
        final_ada_balance,
    ) = soak_api.getSCTokenBalanceListOnMC(context, NUMBER_OF_ACCOUNTS)

    assert (
        context.initial_mc_balance == context.final_mc_balance
    ), f"ERROR: Initial balance of sidechain tokens of all accounts not equal \
        to the final balance on mainchain: \n \
        {context.initial_mc_balance} != {context.final_mc_balance}"


@then("sidechain token transactions are identified as pending")
def step_impl(context):
    response, err = bridge_api.getPendingTxs(
        context.sidechain_cli, context.bridge_params["sidechain_node1"]
    )
    if err:
        assert False, f"ERROR: Unexpected error while getting pending txs: {err}"

    assert (
        hasattr(context, "burn_txs") and context.burn_txs
    ), "context.burn_txs list is empty"

    for burn_tx in context.burn_txs:
        matching_txs = [tx for tx in response.pending if tx.txId == burn_tx.tx_id]
        assert (
            len(matching_txs) == 1
        ), f"ERROR: Expected exactly one tx with hash \
            {burn_tx.tx_id}, but was: {matching_txs}"
        assert (
            hex(matching_txs[0].value) == burn_tx.value
        ), f"ERROR: Tx value doesn't match {hex(matching_txs[0].value)} != \
            {burn_tx.value}"
        assert (
            matching_txs[0].recipient.lower() == burn_tx.recipient.lower()
        ), f"ERROR: Tx recipient doesn't match {matching_txs[0].recipient} != \
            {burn_tx.recipient}"


@then("the merkle root hashes of the transactions are obtained")
def step_impl(context):
    bridge_api.waitForNextSCBlock(context)
    time.sleep(30)

    try:
        signatures = eval(
            context.ethRPC.sidechain_getEpochSignatures(
                context.outgoing_tx_epoch
            ).__str__()
        )
    except Exception as e:
        assert (
            False
        ), f"ERROR: Fail to getEpochSisgnatures for \
            {context.outgoing_tx_epoch} epoch: {e}"

    assert (
        "outgoingTransactions" in signatures.keys()
    ), f'ERROR: key "outgoingTransactions" not found in \
        sidechain_getEpochSignatures return: {signatures}'

    signature_transactions = signatures["outgoingTransactions"]
    assert type(signature_transactions) == list, "ERROR: Outgoing Txs not a list"

    # TODO: use bridge ui backend to get merkle_proof by tx hash
    session = use_fixture(get_db_session, context)
    for tx in context.db_outgoing_txs:
        stmt = select(OutgoingTransaction).where(OutgoingTransaction.id == tx.id)
        current_tx = session.scalars(stmt).one()

        outgoing_proof = eval(
            context.ethRPC.sidechain_getOutgoingTxMerkleProof(
                current_tx.epoch, current_tx.tx_index
            ).__str__()
        )

        assert (
            "proof" in outgoing_proof.keys()
        ), f'ERROR: key "proof" not found in sidechain_getOutgoingTxMerkleProof\
            ({current_tx.epoch}, {current_tx.tx_index}) return:\n {outgoing_proof}'
        assert (
            "bytes" in outgoing_proof["proof"].keys()
        ), f"ERROR: key \"bytes\" not found in sidechain_getOutgoingTxMerkleProof\
            ['proof'] return:\n {outgoing_proof}"
        assert (
            "info" in outgoing_proof["proof"].keys()
        ), f"ERROR: key \"info\" not found in sidechain_getOutgoingTxMerkleProof\
            ['proof'] return:\n {outgoing_proof}"
        assert (
            "merkleRootHash" in outgoing_proof["proof"]["info"].keys()
        ), f"ERROR: key \"merkleRootHash\" not found in outgoing_TxMerkleProof\
            ['proof']['info'] return:\n {outgoing_proof}"

        signatures_root_hashes = [tx["merkleRootHash"] for tx in signature_transactions]
        assert (
            outgoing_proof["proof"]["info"]["merkleRootHash"] in signatures_root_hashes
        ), f"ERROR: MerkleProof from Tx not found within signatures, \n \
            From Tx: {outgoing_proof['proof']['info']['merkleRootHash']} \n \
            From signatures: {signatures_root_hashes}, '"

        current_tx.merkle_proof = outgoing_proof["proof"]["bytes"][2:]
        session.commit()
        logger.debug(f"Updated merkle_proof at: {current_tx}")


@then("sidechain token transactions are no longer pending")
def step_when(context):
    response, err = bridge_api.getPendingTxs(
        context.sidechain_cli, context.bridge_params["sidechain_node1"]
    )
    if err:
        assert False, f"Unexpected error while getting pending txs: {err}"

    assert (
        hasattr(context, "burn_txs") and context.burn_txs
    ), "ERROR: context.burn_txs list is empty"

    for burn_tx in context.burn_txs:
        pending = [tx for tx in response.pending if tx.txId == burn_tx.tx_id]
        assert len(pending) == 0, f"Tx {burn_tx.tx_id} is still pending: {pending}"
