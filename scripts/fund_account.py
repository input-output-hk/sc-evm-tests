from web3 import Web3
import sys
import argparse
from os.path import exists
import os
import re
import json

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)
from utils import utils

default_fund = True
default_import = False
default_unlock = False
default_silent = False
default_wait = True
default_network = "http://127.0.0.1:8545"
default_faucet = "<redacted>"
default_account = "<redacted>"
default_account_key = "<redacted>"
fundkeyFile = "/tmp/fundkey"
default_amount = 1 * pow(10, 18)


def is_faucet_key_available(fundkeyFile=fundkeyFile):
    return exists(fundkeyFile)


def getFaucet(network_name, folder, node_mode="validator", node_number=0):
    if network_name == "":
        fundkeyFile = f"{folder}/fundkey"
        if is_faucet_key_available(fundkeyFile):
            with open(fundkeyFile) as keyfile:
                faucet_key = re.sub(r"[\n\t\s]*", "", keyfile.read())
            faucet_account = default_faucet
        else:
            raise (Exception("Faucet Key not provided"))
    else:
        fundAccountsDict = {}
        if not is_faucet_key_available(f"{folder}/funding-accounts.json"):
            raise (Exception(f"funding-accounts.json not provided on folder {folder}"))
        with open(f"{folder}/funding-accounts.json", "r") as accountsFile:
            fundAccountsDict = json.load(accountsFile)
        network_name = network_name.lower()
        faucet_account = fundAccountsDict[network_name][
            f"{network_name}-{node_mode}-{node_number}"
        ]["account"]
        faucet_key = fundAccountsDict[network_name][
            f"{network_name}-{node_mode}-{node_number}"][
            "key"
        ]
    return faucet_account, faucet_key


def main(
    network_url="",
    network_name="",
    network_id=79,
    node_mode="",
    node_number=0,
    faucet="",
    faucet_key="",
    account="",
    account_key="",
    passphrase="",
    amount=-1,
    fund=default_fund,
    import_flag=default_import,
    unlock=default_unlock,
    silent=default_silent,
    wait=default_wait,
    nonce=None,
):
    if not silent:
        print("Starting fund account script")

    if network_url == "":
        network_url = default_network
    if faucet == "" or faucet_key == "":
        try:
            faucet, faucet_key = getFaucet(
                network_name, "/tmp/test_automation_secrets", node_mode, node_number
            )
        except Exception as e:
            raise f"ERROR: Cannot find fundkey: {e}"
    if account == "":
        account = default_account
    if account_key == "":
        account_key = default_account_key
    if amount == -1:
        amount = default_amount

    w3 = Web3(Web3.HTTPProvider(network_url))
    if not w3.isConnected():
        print("ERROR: Check network connection.")
        return 0

    funder_address = Web3.toChecksumAddress(faucet)
    account = Web3.toChecksumAddress(account)
    amount_to_send = amount

    if not silent:
        print("Balance Funder: ", w3.eth.get_balance(funder_address))
        print("Balance Account: ", w3.eth.get_balance(account))

    if fund:
        if not utils.sendEip1559Tx(
            w3,
            funder_address,
            faucet_key,
            account,
            amount_to_send,
            network_id,
            silent=silent,
            wait=wait,
            nonce=nonce,
        ):
            return False
    if import_flag:
        if not utils.import_account(w3, account, account_key, passphrase, silent):
            return False
        if unlock:
            if not utils.unlock_account(w3, account, passphrase, silent):
                return False
        else:
            if not utils.lock_account(w3, account):
                return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-U",
        "--network-url",
        default="",
        dest="network_url",
        help="Provide network URL to connect to",
        type=str,
    )
    parser.add_argument(
        "-N",
        "--network-name",
        default="STAGING",
        dest="network_name",
        help="Provide network name to connect to",
        type=str,
    )
    parser.add_argument(
        "--network-id",
        default=79,
        dest="network_id",
        help="Provide network id number",
        type=int,
    )
    parser.add_argument(
        "--node-mode",
        default="validator",
        dest="node_mode",
        help="Provide node's mode",
        type=str,
    )
    parser.add_argument(
        "--node-number",
        default=0,
        dest="node_number",
        help="Provide node's number",
        type=int,
    )
    parser.add_argument(
        "-F",
        "--faucet",
        default="",
        dest="faucet",
        help="Provide faucet address.",
        type=str,
    )
    parser.add_argument(
        "-K",
        "--faucet_key",
        default="",
        dest="faucet_key",
        help="Provide key to faucet address.",
        type=str,
    )
    parser.add_argument(
        "--account",
        default="",
        dest="account",
        help="Provide address of account to setup.",
        type=str,
    )
    parser.add_argument(
        "--account_key",
        default="",
        dest="account_key",
        help="Provide key to address.",
        type=str,
    )
    parser.add_argument(
        "--passphrase",
        default="JfH0*6HM^V2f#8M6*",
        dest="passphrase",
        help="Provide passphrase for imported account.",
        type=str,
    )
    parser.add_argument(
        "--amount", default=-1, dest="amount", help="Provide amount to fund.", type=int
    )

    parser.add_argument("--fund", dest="fund", action="store_true")
    parser.add_argument("--import-account", dest="import_flag", action="store_true")
    parser.add_argument("--unlock", dest="unlock", action="store_true")
    parser.add_argument("--silent", dest="silent", action="store_true")
    parser.add_argument("--no-wait", dest="wait", action="store_false")
    parser.set_defaults(
        fund=default_fund,
        import_flag=default_import,
        unlock=default_unlock,
        silent=default_silent,
        wait=default_wait,
    )
    args = parser.parse_args()

    main(
        args.network_url,
        args.network_name,
        args.network_id,
        args.node_mode,
        args.node_number,
        args.faucet,
        args.faucet_key,
        args.account,
        args.account_key,
        args.passphrase,
        args.amount,
        args.fund,
        args.import_flag,
        args.unlock,
        args.silent,
        args.wait,
    )
