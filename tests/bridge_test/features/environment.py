from os.path import exists
import json
from web3 import Web3
from utils import api
import utils.log_wrapper as logger
from steps import bridge_api
from behave import use_fixture
from fixtures import init_db, get_db_session
from sqlalchemy import select, ScalarResult
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from models.db.transaction import OutgoingTransaction
import time


def read_file(filepath):
    with open(filepath, "r") as file:
        file_content = file.read().strip()
        file.close()
    return file_content


def read_cardano_key_file(filepath):
    with open(filepath, "r") as keyFile:
        key_content = json.load(keyFile)
    try:
        key = key_content["cborHex"][4:]  # Remove 5820 from cborHex string
    except Exception as e:
        logger.error(f"Could not parse cardano key file: {e}")
    return key


def before_all(context):
    with open(context.config.userdata["config_file"]) as config_file:
        try:
            confDict = json.load(config_file)
        except Exception as e:
            exit(f"ERROR: Config file not a valid JSON format: {e}")

    bridge_configs, CTL_configs, dbsync_configs, successParse = bridge_api.parseConfig(
        confDict
    )
    assert (
        successParse
    ), f"ERROR: Could not parse config file {context.config.userdata['config_file']}"

    context.bridge_params = bridge_configs
    context.ctl_params = CTL_configs
    context.dbsync_params = dbsync_configs
    context.used_utxo = ""
    sidechain_node = context.bridge_params["sidechain_node1"]
    try:
        w3 = Web3(Web3.HTTPProvider(sidechain_node))
    except Exception as e:
        logger.error(
            f"ERROR: Fail to create Web3 instance for {sidechain_node} node: {e}"
        )
    context.w3 = w3
    assert context.w3 is not None, "ERROR: Web3 instance was not created properly"
    context.total_initial_balance = context.bridge_params["total_balance"]

    assert type(context.total_initial_balance) == int

    context.last_registration_mc_block = {}

    assert exists(
        context.bridge_params["mc_payment_addr_file"]
    ), "ERROR: Mainchain payment address file does not exist"
    assert exists(
        context.bridge_params["mc_payment_skey_file"]
    ), "ERROR: Mainchain payment skey file does not exist"
    assert exists(
        context.bridge_params["mc_sc_token_addr_file"]
    ), "ERROR: Mainchain sidechain token address file does not exist"
    assert exists(
        context.bridge_params["mc_sc_token_skey_file"]
    ), "ERROR: Mainchain sidechain token skey file does not exist"
    assert exists(
        context.bridge_params["sc_payment_addr_file"]
    ), "ERROR: Sidechain address file does not exist"
    assert exists(
        context.bridge_params["sc_payment_key_file"]
    ), "ERROR: Sidechain private key file does not exist"
    assert exists(
        context.bridge_params["sc_genesis_file"]
    ), "ERROR: Sidechain genesis file does not exist"
    assert exists(
        context.bridge_params["generated_accounts_folder"]
    ), "ERROR: Generated accounts folder does not exist"

    assert exists(
        context.ctl_params["registration1"]["spo-signing-key"]
    ), "ERROR: SPO1 cold.skey file does not exist"
    assert exists(
        context.ctl_params["registration1"]["spo-public-key"]
    ), "ERROR: SPO1 cold.vkey file does not exist"
    assert exists(
        context.ctl_params["registration2"]["spo-signing-key"]
    ), "ERROR: SPO2 cold.skey file does not exist"
    assert exists(
        context.ctl_params["registration2"]["spo-public-key"]
    ), "ERROR: SPO2 cold.vkey file does not exist"
    assert exists(
        context.ctl_params["registration3"]["spo-signing-key"]
    ), "ERROR: SPO3 cold.skey file does not exist"
    assert exists(
        context.ctl_params["registration3"]["spo-public-key"]
    ), "ERROR: SPO3 cold.vkey file does not exist"
    assert exists(
        context.ctl_params["registration4"]["spo-signing-key"]
    ), "ERROR: SPO4 cold.skey file does not exist"
    assert exists(
        context.ctl_params["registration4"]["spo-public-key"]
    ), "ERROR: SPO4 cold.vkey file does not exist"

    context.mc_payment_addr = read_file(context.bridge_params["mc_payment_addr_file"])
    context.mc_sc_token_addr = read_file(context.bridge_params["mc_sc_token_addr_file"])
    context.sc_payment_addr = read_file(context.bridge_params["sc_payment_addr_file"])
    context.sc_payment_key = read_file(context.bridge_params["sc_payment_key_file"])

    context.ctl_params["registration1"]["spo-signing-key"] = read_cardano_key_file(
        context.ctl_params["registration1"]["spo-signing-key"]
    )
    context.ctl_params["registration1"]["spo-public-key"] = read_cardano_key_file(
        context.ctl_params["registration1"]["spo-public-key"]
    )
    context.ctl_params["registration2"]["spo-signing-key"] = read_cardano_key_file(
        context.ctl_params["registration2"]["spo-signing-key"]
    )
    context.ctl_params["registration2"]["spo-public-key"] = read_cardano_key_file(
        context.ctl_params["registration2"]["spo-public-key"]
    )
    context.ctl_params["registration3"]["spo-signing-key"] = read_cardano_key_file(
        context.ctl_params["registration3"]["spo-signing-key"]
    )
    context.ctl_params["registration3"]["spo-public-key"] = read_cardano_key_file(
        context.ctl_params["registration3"]["spo-public-key"]
    )
    context.ctl_params["registration4"]["spo-signing-key"] = read_cardano_key_file(
        context.ctl_params["registration4"]["spo-signing-key"]
    )
    context.ctl_params["registration4"]["spo-public-key"] = read_cardano_key_file(
        context.ctl_params["registration4"]["spo-public-key"]
    )

    context.sidechain_cli = context.bridge_params["sc_evm_cli"]
    context.trustless_ctl_cli = context.ctl_params["trustless_ctl_cli"]

    if exists(context.dbsync_params["db_pass"]):
        context.dbsync_pass = read_file(context.dbsync_params["db_pass"])
    else:
        context.dbsync_pass = context.dbsync_params["db_pass"]


def before_feature(context, feature):
    """Log starting of execution of feature
    :param context: Holds contextual information during the running of tests
    :param feature: Holds contextual information about the feature \
        during the running of tests
    :return: None
    """
    if "skip" in feature.tags:
        feature.skip("Marked with @skip")
        return

    # set EVM RPC
    try:
        for i in range(5):
            node = api.Node(context.bridge_params["sidechain_node1"])
            if not node.check_connection():
                print(f"Can not connect, retrying {i+1}/5")
                time.sleep(5)
            else:
                break
        context.ethRPC = node
    except Exception as e:
        assert (
            False
        ), f"ERROR: could not connect to node \
                {context.bridge_params['sidechain_node1']}: {e}"

    # set EVM RPC2
    try:
        for i in range(5):
            node = api.Node(context.bridge_params["sidechain_node2"])
            if not node.check_connection():
                print(f"Can not connect, retrying {i+1}/5")
                time.sleep(5)
            else:
                break
        context.ethRPC2 = node
    except Exception as e:
        assert (
            False
        ), f"ERROR: could not connect to node \
                {context.bridge_params['sidechain_node2']}: {e}"

    # init database
    use_fixture(init_db, context, path=context.bridge_params["db_path"])


def before_scenario(context, scenario):
    if scenario.name == "Verify cross-chain Tx from sidechain to mainchain (lock)":
        __claim_unclaimed_txs(context)


def after_scenario(context, scenario):
    if scenario.name == "Verify cross-chain Tx from sidechain to mainchain (lock)":
        __claim_unclaimed_txs(context)


def __claim_unclaimed_txs(context):
    """Auto recover from unclaimed txs. Total balance must be 100M."""
    session: Session = use_fixture(get_db_session, context)
    stmt = (
        select(OutgoingTransaction)
        .where(OutgoingTransaction.is_claimed.is_not(True))
        .order_by(OutgoingTransaction.epoch)
    )
    db_outgoing_txs: ScalarResult[OutgoingTransaction] = session.scalars(stmt)

    for tx in db_outgoing_txs:
        logger.warn(
            f"Tx {tx.__repr_short__()} is not claimed, we need to "
            "claim it so the total balance == 100M."
        )
        __wait_until_tx_can_be_claimed(context, tx)

        # TODO: if merkle proof is missing use bridge ui backend to obtain it
        if not tx.merkle_proof:
            logger.info(
                f"Tx {tx.__repr_short__()} is missing merkle proof, "
                "trying to get one."
            )
            try:
                merkle_proof = eval(
                    context.ethRPC.sidechain_getOutgoingTxMerkleProof(
                        tx.epoch, tx.tx_index
                    ).__str__()
                )["proof"]["bytes"][2:]
                tx.merkle_proof = merkle_proof
                session.commit()
            except Exception as e:
                logger.error(
                    f"Error with getting merkle proof for {tx}. "
                    f"Active flow scenario may fail. Exception: {e}"
                )
                continue

        # start claim
        logger.info(f"Claiming {tx}")
        tx.claim_start_timestamp = func.now()
        session.commit()

        response, claim_error = bridge_api.claimSCTokenOnMainchain(
            context.sidechain_cli,
            context.bridge_params["sidechain_node1"],
            tx.skey_file_path,
            tx.merkle_proof,
        )
        logger.debug(f"Claim response: {response}")
        if claim_error:
            logger.debug(f"Claim error: {claim_error}")

        # update claim result and end-timestamp in database
        try:
            ctl_response_dict = eval(response)
            if ctl_response_dict["endpoint"] == "ClaimAct":
                tx.is_claimed = True
                logger.info(f"Tx id={tx.id} has been claimed successfully.")
        except Exception as e:
            logger.error(
                "Could not convert CTL response to dictionary: " f"{response}\n{e}"
            )
        finally:
            tx.claim_end_timestamp = func.now()
            session.commit()


def __wait_until_tx_can_be_claimed(context, tx: OutgoingTransaction):
    logger.debug(f"Checking if {tx.__repr_short__()} can be claimed.")
    sc_epoch = context.ethRPC.sidechain_getStatus()["sidechain"]["epoch"]
    if tx.epoch >= sc_epoch:
        bridge_api.wait_until_sc_epoch_has_changed(context)
    if not bridge_api.has_committee_handover_finished(context):
        logger.error(
            "Committee handover is not finished, there are signatures " "to upload."
        )
