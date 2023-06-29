import pytest
import os
import sys
from pytest import fixture

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
grandparentdir = os.path.dirname(parentdir)
sys.path.append(grandparentdir)

import json
import time
from utils import api, utils, log_wrapper as logger
import scripts.fund_account as fund_account

account1 = utils.generate_keys()
account2 = utils.generate_keys()
addr1 = account1["addr"]
skey1 = account1["skey"]
addr2 = account2["addr"]
passphrase = "JfH0*6HM^V2f#8M6*"

error_msg_timeout = "Timeout (15s) for transaction to be processed exceeded"


@fixture(autouse=True)
def test_set_node(network_url):
    for i in range(5):
        pytest.node = api.Node(network_url)
        if not pytest.node.check_connection():
            logger.info(f"Can not connect to node {network_url}, retrying {i+1}/5")
            time.sleep(5)
        else:
            break
    assert (
        pytest.node.check_connection()
    ), f"ERROR: Can not connect to node {network_url}"
    pytest.web3 = utils.getWeb3(network_url)
    utils.setWeb3DefaultAccount(pytest.web3, addr1)


def test_unknown_endpoint():
    try:
        response = api.EthResult(getRPC("request", ["UNKNOWN", []]))
        assert response.isError(), "Non-existent method returned non error"
        actual_message = response["message"]
        expected_messages = [
            "Method not found",
            "The method does not exist / is not available",
        ]
        assert (
            actual_message in expected_messages
        ), f"Error: Unexpected message returned. Expected: \
                {expected_messages}. Actual: {actual_message}"
    except Exception as e:
        assert False, str(e)


def test_net_version(network_version):
    try:
        actual_net_version = int(str(getRPC("net_version", [])))
        assert actual_net_version == int(
            network_version
        ), "Error: Net version does not match"
    except Exception as e:
        assert False, str(e)


def test_eth_chain_id(chain_id):
    try:
        eth_chain_id = int(str(getRPC("eth_chainId", [])), 16)
        assert eth_chain_id == int(chain_id), "Error: Chain ID does not match"
    except Exception as e:
        assert False, str(e)


def test_get_storage_at():
    try:
        response = getRPC("eth_getStorageAt", [addr1, "0x1", "latest"])
        assert not response.isError(), "Error: Could not get storage 1 at latest block"
    except Exception as e:
        assert False, str(e)


def test_estimate_gas():
    try:
        tx = {
            "from": addr1,
            "to": addr2,
            "data": "0x70a082310000000000000000000000006E0d01\
                A76C3Cf4288372a29124A26D4353EE51BE",
        }
        response = getRPC("eth_estimateGas", [tx, "latest"])
        assert not response.isError(), "Error: Could not estimate gas for latest block"
        assert utils.is_hex(response.__str__()), "Error: Non hex return"
    except Exception as e:
        assert False, str(e)


def test_get_logs():
    try:
        params = {"address": addr1}
        response = getRPC("eth_getLogs", [params])
        assert not response.isError(), f"Error: Could not get logs for address {addr1}"
    except Exception as e:
        assert False, str(e)


def test_gas_price():
    try:
        assert (
            int(str(getRPC("eth_gasPrice", [])), 16) == 0
        ), "Error: eth_gasPrice does not work"
    except Exception as e:
        assert False, str(e)


def test_import_raw_key():
    try:
        assert getRPC(
            "personal_importRawKey", [skey1, passphrase]
        ), "Error: Could not import account with raw key"
    except Exception as e:
        assert False, str(e)


def test_get_eth_accounts():
    getRPC("personal_importRawKey", [skey1, passphrase])
    try:
        accounts = eval(getRPC("eth_accounts", []).__str__())
        for idx in range(len(accounts)):
            accounts[idx] = utils.Web3.toChecksumAddress(accounts[idx])
        assert addr1 in accounts, "Error: Account not imported"
    except Exception as e:
        assert False, str(e)


def test_personal_list_accounts():
    getRPC("personal_importRawKey", [skey1, passphrase])
    try:
        accounts = eval(getRPC("personal_listAccounts", []).__str__())
        for idx in range(len(accounts)):
            accounts[idx] = utils.Web3.toChecksumAddress(accounts[idx])
        assert addr1 in accounts, "Error: Account not imported as personal"
    except Exception as e:
        assert False, str(e)


def test_personal_sign():
    getRPC("personal_importRawKey", [skey1, passphrase])
    msg = "0xdeadbeaf"
    try:
        msg_signature = str(getRPC("personal_sign", [msg, addr1, passphrase]))
        assert utils.is_hex(msg_signature), "Error: Could not sign message"
    except Exception as e:
        assert False, str(e)


def test_personal_ec_recover():
    getRPC("personal_importRawKey", [skey1, passphrase])
    msg = "0xdeadbeaf"
    try:
        msg_signature = str(getRPC("personal_sign", [msg, addr1, passphrase]))
        signer_addr = str(getRPC("personal_ecRecover", [msg, msg_signature]))
        signer_addr = utils.Web3.toChecksumAddress(signer_addr)
        assert signer_addr == addr1, "Error: Could not ecRecover msg signer"
    except Exception as e:
        assert False, str(e)


def test_personal_unlock_account():
    try:
        assert getRPC(
            "personal_unlockAccount", [addr1, passphrase]
        ), "Error: Could not unlock personal account"
    except Exception as e:
        assert False, str(e)


def test_get_code():
    try:
        ret = getRPC(
            "eth_getCode", ["0x6C1adDEcc63E7cb56158799A4BF5C8eE5bEB6009", "latest"]
        )
        assert not ret.isError(), "Error: Method doesn't exists"
    except Exception as e:
        assert False, str(e)


def test_block_number():
    try:
        ret = getRPC("eth_getBlockByNumber", ["latest"])
        block_hash = ret["hash"]
        block_number = ret["number"]
        trx_count_by_hash = int(
            str(getRPC("eth_getBlockTransactionCountByHash", [block_hash])), 16
        )
        trx_count_by_number = int(
            str(getRPC("eth_getBlockTransactionCountByNumber", [block_number])), 16
        )
        assert (
            trx_count_by_hash == trx_count_by_number
        ), "Error: Transaction count by hash and by number mismatched"
    except Exception as e:
        assert False, str(e)


def test_stable_block_number():
    try:
        stability_param = getRPC("evmsidechain_getNetworkInfo", [])[
            "stabilityParameter"
        ]
        stable = getRPC("evmsidechain_getBlockByNumber", ["stable"])
        latest = getRPC("evmsidechain_getBlockByNumber", ["latest"])
        stable_number = int(stable["number"], 16)
        latest_number = int(latest["number"], 16)
        block_number = getRPC("eth_getBlockByNumber", ["latest"])["number"]
        if latest_number < stability_param:
            assert (
                False
            ), f"To correctly test evmsidechain_getBlockByNumber with stable, \
                we have to be at least at block {stability_param}, \
                but we are at block {int(block_number, 16)}."
        assert (latest_number - stability_param) - stable_number in (
            0,
            1,
        ), "Error: invalid stable block number"
    except Exception as e:
        assert False, str(e)


def test_get_block_hash():
    try:
        block_hash = getRPC("eth_getBlockByNumber", ["latest"])["hash"]
        ret = getRPC("eth_getBlockByHash", [block_hash])
        returned_block_hash = ret["hash"]
        assert (
            returned_block_hash == block_hash
        ), "Error: Could not get hash of latest block"
    except Exception as e:
        assert False, str(e)


def test_eth_get_balance(
    network_url, network_name, network_version, node_mode, node_number
):
    try:
        check_balance(
            network_url, network_name, network_version, node_mode, node_number
        )
        balance = get_eth_balance(addr1)
        assert balance >= 50, "Error: Could not fund account"
    except Exception as e:
        assert False, str(e)


def test_eth_get_legacy_transaction_by_hash(
    chain_id, network_url, network_name, network_version, node_mode, node_number
):
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    try:
        nonce = int(str(getRPC("eth_getTransactionCount", [addr1, "latest"])), 16)
        txLegacyReceipt = utils.sendLegacyTx(
            pytest.web3,
            addr1,
            skey1,
            addr2,
            11,
            chain_id,
            silent=False,
            wait=True,
            nonce=nonce,
        )
        legacyTxHash = txLegacyReceipt["transactionHash"].hex()
        legacyTx = getRPC("eth_getTransactionByHash", [legacyTxHash])
        assert legacyTx["type"] == "0x00"
        assert legacyTx["to"].upper() == addr2.upper()
        check_block_hash_and_number(legacyTx)
    except Exception as e:
        assert False, str(e)


def test_eth_get_eip_1559_transaction_by_hash_with_contract_compile_and_deploy(
    network_url, network_name, network_version, node_mode, node_number
):
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    try:
        deploymentResult = utils.compileAndDeployContract(
            "Hello",
            os.path.dirname(os.path.abspath(__file__)),
            "",
            pytest.web3,
            "",
            addr1,
            skey1,
            silent=False,
        )

        txEip1559Receipt = deploymentResult["tx_receipt"]
        eip1559TxHash = txEip1559Receipt["transactionHash"].hex()
        eip1559Tx = getRPC("eth_getTransactionByHash", [eip1559TxHash])

        assert eip1559Tx["type"] == "0x02"
        assert eip1559Tx["to"] is None  # Because it's a contract creation
        assert eip1559Tx["accessList"] == []
        assert eip1559Tx["maxFeePerGas"] == "0x77359400"
        assert eip1559Tx["maxPriorityFeePerGas"] == "0x3b9aca00"
        check_block_hash_and_number(eip1559Tx)
    except Exception as e:
        assert False, str(e)


def test_eth_get_eip_2930_transaction_by_hash(
    chain_id, network_url, network_name, network_version, node_mode, node_number
):
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    try:
        nonce = int(str(getRPC("eth_getTransactionCount", [addr1, "latest"])), 16)
        txEip2930Receipt = utils.sendEip2930Tx(
            pytest.web3,
            addr1,
            skey1,
            addr2,
            12,
            chain_id,
            silent=False,
            wait=True,
            nonce=nonce,
        )
        eip2930TxHash = txEip2930Receipt["transactionHash"].hex()
        eip2930Tx = getRPC("eth_getTransactionByHash", [eip2930TxHash])
        assert eip2930Tx["type"] == "0x01"
        assert eip2930Tx["to"].upper() == addr2.upper()
        check_block_hash_and_number(eip2930Tx)
    except Exception as e:
        assert False, str(e)


def test_eth_send_transaction(
    network_url, network_name, network_version, node_mode, node_number
):
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    try:
        tx = {"from": addr1, "to": addr2, "value": 1 * 10**18}
        tx_hash = getRPC("eth_sendTransaction", [tx])
        assert wait_for_tx(tx_hash), "Error: Could not send transaction"
    except Exception as e:
        assert False, str(e)

    try:
        tx_result = eval(str(getRPC("eth_getTransactionByHash", [str(tx_hash)])))
        tx_result["from"] = utils.Web3.toChecksumAddress(tx_result["from"])
        tx_result["to"] = utils.Web3.toChecksumAddress(tx_result["to"])
        assert tx_result["from"] == tx["from"], "Error: TX from mismatch"
        assert tx_result["to"] == tx["to"], "Error: TX to mismatch"
        assert (
            int(str(tx_result["value"]), 16) == tx["value"]
        ), "Error: TX Value mismatch"
    except Exception as e:
        assert False, str(e)


def test_eth_call():
    try:
        tx = {
            "from": addr1,
            "to": addr2,
            "data": "0x70a082310000000000000000000000006E0d\
                01A76C3Cf4288372a29124A26D4353EE51BE",
        }
        response = getRPC("eth_call", [tx, "latest"])
        assert not response.isError(), "Error: Could not eth_call at latest block"
    except Exception as e:
        assert False, str(e)


def test_eth_block_number_stable_not_available():
    try:
        ret = getRPC("eth_getBlockByNumber", ["stable"])
        assert (
            ret["message"] == "Invalid params"
        ), "Error: stable should not be available for eth_getBlockByNumber"
    except Exception as e:
        assert False, str(e)


def test_eth_block_number_negative():
    try:
        ret = getRPC("eth_getBlockByNumber", ["-10"])
        assert (
            ret["message"] == "Invalid params"
        ), "Error: eth_getBlockByNumber should not accept a negative number"
    except Exception as e:
        assert False, str(e)


def test_eth_block_hash():
    try:
        block_hash = getRPC("eth_getBlockByNumber", ["latest"])["hash"]
        ret = getRPC("eth_getBlockByHash", [block_hash])
        returned_block_hash = ret["hash"]
        assert (
            returned_block_hash == block_hash
        ), "Error: Could not get hash of latest block"
    except Exception as e:
        assert False, str(e)


def test_new_account(
    network_url, network_name, network_version, node_mode, node_number
):
    getRPC("personal_importRawKey", [skey1, passphrase])
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    try:
        new_account_object = getRPC("personal_newAccount", [passphrase])
        new_account = new_account_object.__str__()
        assert (
            not new_account_object.isError()
        ), f"Error: Could not create new account: {new_account}"
    except Exception as e:
        assert False, str(e)

    try:
        balance = int(getRPC("eth_getBalance", [new_account, "latest"]).__str__(), 16)
        assert balance == 0, "Error: Account created with non 0 balance"
    except Exception as e:
        assert False, str(e)

    try:
        tx = {"from": addr1, "to": new_account, "value": 1 * 10**18}
        tx_hash = pytest.node.personal_sendTransaction(json.dumps(tx), passphrase)
        assert (
            not tx_hash.isError()
        ), f"Error: Could not send transaction: {str(tx_hash)}"
        assert wait_for_tx(tx_hash), error_msg_timeout
        balance = int(getRPC("eth_getBalance", [new_account, "latest"]).__str__(), 16)
        assert balance == tx["value"]
    except Exception as e:
        assert False, str(e)

    try:
        tx = {"from": new_account, "to": addr1, "value": 1 * 10**18}
        tx_hash = pytest.node.personal_sendTransaction(json.dumps(tx), passphrase)

        assert wait_for_tx(tx_hash), error_msg_timeout
    except Exception as e:
        assert False, str(e)


def test_lock_account(
    network_url, network_name, network_version, node_mode, node_number
):
    getRPC("personal_importRawKey", [skey1, passphrase])
    check_balance(network_url, network_name, network_version, node_mode, node_number)
    balance_before_lock = get_eth_balance(addr1)
    try:
        assert getRPC(
            "personal_lockAccount", [addr1]
        ), "Error: Could not lock personal account"
    except Exception as e:
        assert False, str(e)

    try:
        tx = {
            "from": addr1,
            "to": addr2,
            "data": "0x70a082310000000000000000000000006E0d0\
                1A76C3Cf4288372a29124A26D4353EE51BE",
        }
        tx_hash = getRPC("eth_sendTransaction", [tx])
        assert (
            tx_hash.isError()
        ), "Error: Transaction from a locked account should not be accepted."
        actual = tx_hash["data"][0]["message"]
        expected = "account is locked or unknown"
        assert (
            expected == actual
        ), f"Error: Expected error message: {expected}, actual error message: {actual}"
    except Exception as e:
        assert False, str(e)

    assert get_eth_balance(addr1) == balance_before_lock

    try:
        tx = {"from": addr1, "to": addr2, "value": 1 * 10**18}
        tx_hash = pytest.node.personal_sendTransaction(json.dumps(tx), passphrase)
        assert (
            not tx_hash.isError()
        ), f"Error: Could not send transaction: {str(tx_hash)}"
        assert wait_for_tx(tx_hash), error_msg_timeout
    except Exception as e:
        assert False, str(e)


def wait_for_tx(tx_hash):
    for i in range(60):
        tx_receipt = str(getRPC("eth_getTransactionReceipt", [str(tx_hash)]))
        time.sleep(1.0)
        if not tx_receipt == "None":
            tx_receipt = eval(tx_receipt)
            return True
    return False


def get_eth_balance(addr):
    return int(str(getRPC("eth_getBalance", [addr, "latest"])), 16) / 10**18


def check_block_hash_and_number(transaction):
    block_hash = transaction["blockHash"]
    block_number = transaction["blockNumber"]
    block = getRPC("eth_getBlockByHash", [block_hash])
    tx_in_block = next(
        (tx for tx in block["transactions"] if tx["hash"] == transaction["hash"]), None
    )
    assert (
        tx_in_block is not None
    ), f"Error: Tx with hash {transaction['hash']} is not found in block {block}"
    assert (
        tx_in_block["blockHash"] == block_hash
    ), f"Error: 'blockHash' is not available in tx_in_block \
        {tx_in_block} inside block {block}"
    assert (
        tx_in_block["blockNumber"] == block_number
    ), f"Error: 'blockNumber' is not available in tx_in_block \
        {tx_in_block} inside block {block}"


def getRPC(call, params):
    params_string = utils.build_params_string(params)
    call_string = f"pytest.node.{call}({params_string})"
    for i in range(5):
        try:
            call = eval(call_string)
            break
        except Exception as e:
            logger.info(f"Can not make call {call}, retrying {i+1}/5")
            logger.debug(e)
            time.sleep(5)
    return call


def check_balance(network_url, network_name, network_version, node_mode, node_number):
    balance = get_eth_balance(addr1)
    if balance < 50:
        logger.info(f"Current balance is {balance}, funding...")
        fund_account.main(
            network_url=network_url,
            network_name=network_name,
            network_id=network_version,
            node_mode=node_mode,
            node_number=node_number,
            account=addr1,
            amount=50 * 10**18,
            fund=True,
            import_flag=False,
            unlock=False,
            silent=True,
            wait=True,
        )
