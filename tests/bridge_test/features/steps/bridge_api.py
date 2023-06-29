import os
import sys
import subprocess

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
grandparent = os.path.dirname(parent)
tests_folder_path = os.path.dirname(os.path.dirname(grandparent))
sys.path.append(tests_folder_path)
import datetime
import time
from utils import cardano_cli, utils
import utils.log_wrapper as logger
import string
import json
from types import SimpleNamespace

CLAIM_TIMEOUT = 3600
BURN_TIMEOUT = 3600
REGISTER_TIMEOUT = 1200
SC_EVM_CLI_TIMEOUT = 1200


def parseConfig(confDict):
    try:
        sidechain_node1 = confDict["bridge"]["sidechain_node1"]
        sidechain_node2 = confDict["bridge"]["sidechain_node2"]
        if not sidechain_node1.startswith("http"):
            confDict["bridge"]["sidechain_node1"] = "http://" + os.getenv(
                sidechain_node1
            )
        if not sidechain_node2.startswith("http"):
            confDict["bridge"]["sidechain_node2"] = "http://" + os.getenv(
                sidechain_node2
            )
        if "db-sync" not in confDict.keys():
            confDict["db-sync"] = {}
        return confDict["bridge"], confDict["CTL"], confDict["db-sync"], True
    except Exception as e:
        logger.error(f"JSON key not found: {e}")
        return None, None, None, False


def read_file(filepath):
    if not os.path.exists(filepath):
        logger.error(f"File {filepath} does not exist.")
        return False
    with open(filepath, "r") as file:
        file_content = file.read().strip()
        file.close()
        return file_content


def run_command(command: list | str, timeout=120, logs_enabled=True, shell=False):
    """Run subprocess with timeout (120 seconds by default)."""
    # If passing a string, either shell must be True or else the string must
    # simply name the program to be executed without specifying any arguments.
    if isinstance(command, str) and not shell:
        command = command.split(" ")
        if logs_enabled:
            logger.debug(f"Command converted to list: {command}")
    else:
        if logs_enabled:
            logger.debug(f"Running command: {command} with timeout: {timeout}")

    try:
        result = subprocess.run(
            command, timeout=timeout, capture_output=True, shell=shell, encoding="utf-8"
        )
        if logs_enabled:
            logger.debug(f"Command stdout: {result.stdout}")
            if result.stderr:
                logger.debug(f"Command stderr: {result.stderr}")
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout expired.")
        if logs_enabled:
            logger.error({e})
        raise
    except Exception as e:
        logger.error("Unknown error.")
        if logs_enabled:
            logger.error({e})
        raise


def get_latest_mc_status(context):
    cardano_network = context.bridge_params["mainchain_network"]
    command = f"cardano-cli query tip --{cardano_network}"
    try:
        query = eval(cardano_cli.getCardanoCliValue(command, ""))
        context.cardano_tip = query["slot"]
        context.cardano_block = query["block"]
        context.cardano_epoch = query["epoch"]
        context.cardano_syncProgress = query["syncProgress"]
        logger.info(f"Latest mc block: {context.cardano_block}")
    except Exception as e:
        assert False, f"ERROR: Could not query MC for latest status: {e}"
    assert True


def getUTxOFromAccount(address, network):
    utxos = cardano_cli.getAddrUTxOs(address, network)
    for utxo in utxos:
        if utxos[utxo]["value"]["lovelace"] > 2500000:
            return utxo
    return False


def checkUTxOExists(address, utxo, network):
    utxos = cardano_cli.getAddrUTxOs(address, network)
    return utxo in utxos


def getGenesisHash(sidechain_cli, file_location):
    command = f"{sidechain_cli} genesis-hash {file_location}"
    try:
        hash, err = run_command(command, timeout=SC_EVM_CLI_TIMEOUT)
    except Exception as e:
        logger.error(f"Could not read genesis-hash from file {file_location}: {e}")
    return hash.strip()


def getECDSAPublicKey(sidechain_cli, private_key):
    command = f"{sidechain_cli} derive-key --type ecdsa {private_key}"
    try:
        pubkey, err = run_command(command, timeout=SC_EVM_CLI_TIMEOUT)
        pubkey = eval(pubkey)
    except Exception as e:
        logger.error(f"Could not get ECDSA Public key: {err}\n{e}")
    return pubkey


def getSignatures(
    sidechain_cli,
    genesis_hash,
    sidechain_id,
    registration_utxo,
    spo_signing_key,
    sc_signing_key,
    genesis_utxo,
    threshold_numerator,
    threshold_denominator,
):
    command = (
        f"{sidechain_cli} generate-signature "
        f"--genesis-hash {genesis_hash} "
        f"--sidechain-id {sidechain_id} "
        f"--registration-utxo {registration_utxo} "
        f"--spo-signing-key {spo_signing_key} "
        f"--sidechain-signing-key {sc_signing_key} "
        f"--genesis-utxo {genesis_utxo} "
        f"--threshold-numerator {threshold_numerator} "
        f"--threshold-denominator {threshold_denominator}"
    )
    try:
        keys, err = run_command(command)
        keys_dict = eval(keys)
        return keys_dict
    except Exception as e:
        logger.error(
            f"Could not get signatures for registration:\n \
                      Command: {command}\n \
                      Result: {keys}\n \
                      Error: {err}\n{e}"
        )
        return False


def get_contract_addresses(
    trustless_ctl_cli,
    mc_payment_skey_file,
    genesisUtxo,
    chainId,
    sidechain_genesis_hash,
    genesisMint,
    numerator,
    denominator,
):
    command = (
        f"{trustless_ctl_cli} addresses "
        f"--payment-signing-key-file {mc_payment_skey_file} "
        f"--genesis-committee-hash-utxo {genesisUtxo} "
        f"--sidechain-id {chainId} "
        f"--sidechain-genesis-hash {sidechain_genesis_hash} "
        f"--threshold-numerator {numerator} "
        f"--threshold-denominator {denominator}"
    )
    if genesisMint is not None:
        command += f" --genesis-mint-utxo {genesisMint}"
    ctl_response, ctl_error = run_command(command)
    try:
        json_ctl_response = eval(ctl_response)
    except Exception as e:
        assert (
            False
        ), f"ERROR: {e}\nCTL Response: {ctl_response}\n CTL Error: {ctl_error}"
    assert (
        "addresses" in json_ctl_response.keys()
    ), f'ERROR: key "addresses" not found in CTL addresses return\n{json_ctl_response}'
    assert (
        "CommitteCandidateValidator" in json_ctl_response["addresses"].keys()
    ), f"ERROR: key \"CommitteCandidateValidator\" not found in \
       CTL addresses['addresses'] return\n{json_ctl_response}"

    assert "mintingPolicies" in json_ctl_response.keys(), (
        'ERROR: key "mintingPolicies" not found in CTL addresses return\n'
        + f"{json_ctl_response}"
    )
    assert (
        "FuelMintingPolicyId" in json_ctl_response["mintingPolicies"].keys()
    ), f"ERROR: key \"FuelMintingPolicyId\" not found in CTL \
       addresses['mintingPolicies'] return\n{json_ctl_response}"

    return (
        json_ctl_response["addresses"]["CommitteCandidateValidator"],
        json_ctl_response["mintingPolicies"]["FuelMintingPolicyId"] + ".4655454c",
    )


def registerSPO(context, new_registration):
    registration_utxo = getUTxOFromAccount(
        context.mc_payment_addr, context.bridge_params["mainchain_network"]
    )
    logger.info(f"Registration UTxO: {registration_utxo}")
    if registration_utxo == context.used_utxo:
        new_block_received = waitForNextMCBlock(context)
        assert new_block_received, "ERROR: Cannot receive new MC block"
        registration_utxo = getUTxOFromAccount(
            context.mc_payment_addr, context.bridge_params["mainchain_network"]
        )
        logger.info(f"New registration UTxO: {registration_utxo}")
    assert registration_utxo, "ERROR: Could not find UTxO with enough funds on account"
    context.last_registration_mc_block[
        context.ctl_params[new_registration]["spo-public-key"]
    ] = context.cardano_block
    sc_public_key = getECDSAPublicKey(
        context.sidechain_cli,
        context.ctl_params[new_registration]["sidechain-signing-key"],
    )["publicCompressed"]
    logger.info(
        "SPO Public key to register: "
        f"{context.ctl_params[new_registration]['spo-public-key']}"
    )

    signatures = getSignatures(
        context.sidechain_cli,
        context.sidechain_genesis_hash,
        context.ctl_params["sidechainParameters"]["chainId"],
        registration_utxo,
        context.ctl_params[new_registration]["spo-signing-key"],
        context.ctl_params[new_registration]["sidechain-signing-key"],
        context.ctl_params["sidechainParameters"]["genesisUtxo"],
        context.ctl_params["sidechainParameters"]["threshold"]["numerator"],
        context.ctl_params["sidechainParameters"]["threshold"]["denominator"],
    )
    assert signatures, "ERROR: Could not get signatures from SC_EVM CLI"
    spo_public_key = signatures["spoPublicKey"]
    assert (
        spo_public_key == context.ctl_params[new_registration]["spo-public-key"]
    ), f"ERROR: SPO Public key does not match derived one\n, \
       {context.ctl_params[new_registration]['spo-public-key']} != {spo_public_key}"

    register_cmd = (
        f"{context.trustless_ctl_cli} register "
        f"--payment-signing-key-file {context.bridge_params['mc_payment_skey_file']} "
        f"--sidechain-id {context.ctl_params['sidechainParameters']['chainId']} "
        f"--genesis-committee-hash-utxo "
        f"{context.ctl_params['sidechainParameters']['genesisUtxo']} "
        f"--sidechain-genesis-hash {context.sidechain_genesis_hash} "
        f"--threshold-numerator "
        f"{context.ctl_params['sidechainParameters']['threshold']['numerator']} "
        f"--threshold-denominator "
        f"{context.ctl_params['sidechainParameters']['threshold']['denominator']} "
        f"--spo-public-key {signatures['spoPublicKey']} "
        f"--sidechain-public-key {sc_public_key} "
        f"--spo-signature {signatures['spoSignature']} "
        f"--sidechain-signature {signatures['sidechainSignature']} "
        f"--registration-utxo {registration_utxo}"
    )
    if context.ctl_params["sidechainParameters"]["genesisMint"] is not None:
        register_cmd += (
            " --genesis-mint-utxo "
            + f"{context.ctl_params['sidechainParameters']['genesisMint']}"
        )
    ctl_response, ctl_error = run_command(register_cmd, timeout=REGISTER_TIMEOUT)
    try:
        ctl_response = eval(ctl_response)
    except Exception as e:
        assert (
            False
        ), f"ERROR: CTL Response: {ctl_response}\nCTL Error: {ctl_error}\n {e}"
    assert (
        ctl_response["endpoint"] == "CommitteeCandidateReg"
    ), f"ERROR: Could not register: {ctl_response}"
    # Verify that UTxO was consumed
    waitForNextMCBlock(context)  # Give time to MC node to sync
    assert not checkUTxOExists(
        context.mc_payment_addr,
        registration_utxo,
        context.bridge_params["mainchain_network"],
    ), (
        f"ERROR: UTxO not consumed {registration_utxo} "
        + f"from account {context.mc_payment_addr}"
    )
    context.used_utxo = registration_utxo
    return spo_public_key


def deregisterSPO(context, spo_public_key):
    logger.info(f"SPO Public key to deregister: {spo_public_key}")
    # Determine if the SPO to deregister is Pending registration or not
    status = ""
    for candidate in context.current_candidates:
        if spo_public_key in candidate["mainchainPubKey"] and (
            status == "Pending" or status == ""
        ):  # For multiple registrations, keep non-pending
            status = candidate["registrationStatus"]
    assert status != "", "ERROR: SPO key not registered, so cannot be deregistered"
    context.deregistration_status = status

    deregister_cmd = (
        f"{context.trustless_ctl_cli} deregister "
        f"--payment-signing-key-file {context.bridge_params['mc_payment_skey_file']} "
        f"--sidechain-id {context.ctl_params['sidechainParameters']['chainId']} "
        f"--genesis-committee-hash-utxo "
        f"{context.ctl_params['sidechainParameters']['genesisUtxo']} "
        f"--sidechain-genesis-hash {context.sidechain_genesis_hash} "
        f"--threshold-numerator "
        f"{context.ctl_params['sidechainParameters']['threshold']['numerator']} "
        f"--threshold-denominator "
        f"{context.ctl_params['sidechainParameters']['threshold']['denominator']} "
        f"--spo-public-key {spo_public_key}"
    )
    if context.ctl_params["sidechainParameters"]["genesisMint"] is not None:
        deregister_cmd += (
            " --genesis-mint-utxo "
            + f"{context.ctl_params['sidechainParameters']['genesisMint']}"
        )
    ctl_response, ctl_error = run_command(deregister_cmd, timeout=REGISTER_TIMEOUT)
    try:
        ctl_response = eval(ctl_response)
    except Exception as e:
        assert (
            False
        ), f"ERROR: CTL Response: {ctl_response}\nCTL Error: {ctl_error}\n{e}"
    context.just_deregistered_spo_public_key = spo_public_key
    assert (
        ctl_response["endpoint"] == "CommitteeCandidateDereg"
    ), f"ERROR: Could not deregister: {ctl_response}"


def waitForNextSCBlock(context):
    # Wait for a new sc block before querying for pending transactions
    success = True
    try:
        original_sc_block = int(
            context.ethRPC.eth_getBlockByNumber("latest")["number"], 16
        )
        current_sc_block = original_sc_block
        i = 0
        while current_sc_block != original_sc_block + 1:
            i = i + 1
            time.sleep(1)
            current_sc_block = int(
                context.ethRPC.eth_getBlockByNumber("latest")["number"], 16
            )
            if i == 60:  # No block in 1 minute
                success = False
                break
    except Exception as e:
        assert success, f"ERROR: Could not get latest SC block: {e}"


def waitForNextMCBlock(context):
    get_latest_mc_status(context)
    old_block = context.cardano_block
    latest_block = old_block
    logger.info("Waiting for next MC block...")
    i = 0
    success = True
    while latest_block == old_block:
        time.sleep(10)
        get_latest_mc_status(context)
        latest_block = context.cardano_block
        if i == 24:  # No block in 4 minutes
            success = False
            break
        i = i + 1
    return success


def get_mc_status_from_sc(context):
    try:
        mc_info = context.ethRPC.sidechain_getStatus()
        context.sc_epoch_phase = mc_info["sidechain"]["epochPhase"]
        context.sc_epoch = mc_info["sidechain"]["epoch"]
        context.cardano_tip_from_SC = mc_info["mainchain"]["slot"]
        context.cardano_best_block_from_SC = mc_info["mainchain"]["bestBlock"]["number"]
        context.cardano_epoch_from_SC = mc_info["mainchain"]["epoch"]
    except Exception as e:
        logger.error(e)
        assert False, f"ERROR: Could not get mainchain status from sidechain {e}"
    assert (
        type(context.sc_epoch_phase) == str
    ), f"ERROR: SC epoch phase not a string, {context.sc_epoch_phase}"
    assert (
        type(context.sc_epoch) == int
    ), f"ERROR: SC epoch not an int, {context.sc_epoch}"
    assert (
        type(context.cardano_tip_from_SC) == int
    ), f"ERROR: MC tip not an int, {context.cardano_tip_from_SC}"
    assert (
        type(context.cardano_best_block_from_SC) == int
    ), f"ERROR: MC best block not an int, {context.cardano_best_block_from_SC}"
    assert (
        type(context.cardano_epoch_from_SC) == int
    ), f"ERROR: SC epoch not an int, {context.cardano_epoch_from_SC}"


def lockSCToken(sidechain_cli, nodeURL, sc_addr, sc_key, mc_destination_addr, amount):
    try:
        bech32_destination_addr, err = run_command(
            ["bash", "-c", f"bech32 <<< {mc_destination_addr}"]
        )
        bech32_destination_addr = bech32_destination_addr.strip()
    except Exception as e:
        assert False, f"ERROR: Could not convert to bech32 address: {err}\n{e}"
    try:
        nonce = nodeURL.eth_getTransactionCount(sc_addr, "latest")
        nonce = int(str(nonce), 16)
    except Exception as e:
        assert False, f"ERROR: Could not get nonce of sc account: {e}"
    try:
        command = (
            f"{sidechain_cli} create-lock-tx "
            f"--nonce {nonce} --private-key {sc_key} "
            f"{bech32_destination_addr} {amount}"
        )
        lock_tx_hash, err = run_command(command, timeout=SC_EVM_CLI_TIMEOUT)
        lock_tx_hash = lock_tx_hash.strip()
        assert lock_tx_hash != "", "ERROR: Empty response from create-lock-tx"
    except Exception as e:
        assert False, f"ERROR: Could not create lock transaction: {err}\n{e}"
    try:
        raw = nodeURL.eth_sendRawTransaction(f"0x{lock_tx_hash}")
        assert utils.is_hex(str(raw)), f"ERROR: Could not send raw transaction: {raw}"
        receipt = "None"
        i = 0
        while receipt == "None" and i < 60:
            time.sleep(1)
            i = i + 1
            receipt = str(nodeURL.eth_getTransactionReceipt(str(raw)))
        receipt = eval(receipt)
        assert (
            receipt["status"] == "0x1"
        ), f"ERROR: Transaction return wrong status: {receipt}"
    except Exception as e:
        assert False, f"ERROR: Could not lock amount {amount}: {e}\n{raw}"
    return bech32_destination_addr


def claimSCTokenOnMainchain(
    cli,
    payment_skey,
    sidechain_id,
    genesis_hash,
    genesis_utxo,
    genesis_mint,
    threshold_num,
    threshold_den,
    merkle_proof,
):
    claim_cmd = (
        f"{cli} claim "
        f"--payment-signing-key-file {payment_skey} "
        f"--sidechain-id {sidechain_id} "
        f"--sidechain-genesis-hash {genesis_hash} "
        f"--genesis-committee-hash-utxo {genesis_utxo} "
        f"--threshold-numerator {threshold_num} "
        f"--threshold-denominator {threshold_den} "
        f"--combined-proof {merkle_proof}"
    )
    if genesis_mint is not None:
        claim_cmd += f" --genesis-mint-utxo {genesis_mint} "
    try:
        ctl_response, ctl_error = run_command(claim_cmd, timeout=CLAIM_TIMEOUT)
    except Exception as e:
        assert False, f"ERROR: Could not run claim CTL command: {e}"
    return ctl_response, ctl_error


def burnSCTokens(
    cli,
    mc_payment_key,
    sidechain_id,
    genesis_hash,
    genesis_utxo,
    genesis_mint,
    threshold_num,
    threshold_den,
    burn_amount,
    recipient
):
    ctl_command = (
        f"{cli} burn "
        f"--payment-signing-key-file {mc_payment_key} "
        f"--sidechain-id {sidechain_id} "
        f"--sidechain-genesis-hash {genesis_hash} "
        f"--genesis-committee-hash-utxo {genesis_utxo} "
        f"--threshold-numerator {threshold_num} "
        f"--threshold-denominator {threshold_den} "
        f"--amount {burn_amount} "
        f"--recipient {recipient[2:]}"
    )  # Remove 0x from address
    if genesis_mint is not None:
        ctl_command += f" --genesis-mint-utxo {genesis_mint}"
    try:
        ctl_response, ctl_error = run_command(ctl_command, timeout=BURN_TIMEOUT)
        ctl_response_dict = eval(ctl_response)
    except subprocess.TimeoutExpired:
        assert False, "Timeout when executing burn-sc-token command"
    except Exception as e:
        assert False, (
            f"ERROR: {e}\nCTL Command: {ctl_command}\n"
            + f"CTL Response: {ctl_response}\nCTL Error: {ctl_error}"
        )
    assert (
        "endpoint" in ctl_response_dict.keys()
    ), 'ERROR: key "endpoint" not found in burn token return'
    assert (
        "transactionId" in ctl_response_dict.keys()
    ), 'ERROR: key "transactionId" not found in burn token return'
    assert (
        ctl_response_dict["endpoint"] == "BurnAct"
    ), f"ERROR: Sidechain token not submitted (burnt): {ctl_response}"
    transactionId = ctl_response_dict["transactionId"]
    assert all(
        c in string.hexdigits for c in transactionId
    ), f"ERROR: transaction Id returned not a hex string: {transactionId}"
    return transactionId


def getSCTokenBalanceOnMC(context, mc_address):
    utxos = cardano_cli.getAddrUTxOs(
        mc_address, context.bridge_params["mainchain_network"]
    )
    assert utxos is not False, f"ERROR: Could not get UTxOs of address {mc_address}"
    tokensDict = cardano_cli.getTokenListFromTxHash(utxos)
    if context.bridge_params["mc_sc_token_policy_id"] in tokensDict.keys():
        sc_token_balance = tokensDict[context.bridge_params["mc_sc_token_policy_id"]]
    else:
        sc_token_balance = 0
    assert type(sc_token_balance) == int, "ERROR: Balance is not an integer"
    return sc_token_balance


def getSignaturesToUpload(context):
    try:
        root_hashes = context.ethRPC.sidechain_getSignaturesToUpload(100).__str__()
    except Exception as e:
        assert False, f"ERROR: Could not get signatures to upload: {e}"
    try:
        root_hashes = eval(root_hashes)
    except Exception as e:
        assert False, f"ERROR: Could not convert result to dictionary: {e}"
    return root_hashes


def getPendingTxs(sidechain_cli, sc_node_url):
    pending_txs_cmd = f"{sidechain_cli} pending-txs --sc-evm-url {sc_node_url}"
    try:
        # Use SimpleNamespace to map dict keys to object attributes
        response_raw, error = run_command(pending_txs_cmd)
        response = json.loads(response_raw, object_hook=lambda d: SimpleNamespace(**d))
        return response, error
    except json.JSONDecodeError as e:
        logger.error(f"{type(e)}: {e.msg}\ndocument being parsed:\n{e.doc}")
        raise
    except Exception as e:
        logger.error(f"Could not run pending txs CLI command: {e.msg}\n{e}")
        raise


def getIncomingTxs(sidechain_cli, sc_node_url, from_block):
    incoming_txs_cmd = (
        f"{sidechain_cli} search-incoming-txs --sc-evm-url {sc_node_url} "
        f"--from {from_block}"
    )
    try:
        logger.info(f"Running cli search incoming txs cmd: {incoming_txs_cmd}")
        response, error = run_command(incoming_txs_cmd)
    except Exception as e:
        assert False, (
            "ERROR: Could not run search incoming txs CLI command from block "
            + f"{from_block}: {e}"
        )
    return response, error


def wait_until_sc_epoch_has_changed(context):
    sc_status = context.ethRPC.sidechain_getStatus()["sidechain"]
    logger.info(
        f"Current sc epoch is {sc_status['epoch']}. " "Waiting for the next epoch."
    )
    current_timestamp = int(time.time())
    next_epoch_timestamp = sc_status["nextEpochTimestamp"]
    timeout = int(next_epoch_timestamp, 0) + 60
    epoch_has_changed = False

    while current_timestamp < timeout:
        wait_time = str(datetime.timedelta(seconds=timeout - current_timestamp))
        logger.debug(f"Waiting {wait_time} for the next epoch.")
        time.sleep(60)
        current_sc_status = context.ethRPC.sidechain_getStatus()["sidechain"]
        if current_sc_status["epoch"] > sc_status["epoch"]:
            epoch_has_changed = True
            break
        current_timestamp = int(time.time())

    assert epoch_has_changed, "TimeoutError: didn't get to next epoch in time"
    waitForNextSCBlock(context)  # Wait until the first block after new epoch


def has_committee_handover_finished(context):
    logger.info("Checking if there are no signatures to upload.")
    timeout = int(time.time()) + 300
    while int(time.time()) < timeout:
        root_hashes = getSignaturesToUpload(context)
        if root_hashes == []:
            logger.info(
                "Committee handover has finished. There are no signatures to upload."
            )
            return True
        logger.debug(f"Waiting for signatures to upload {root_hashes}")
        time.sleep(30)
    return False
