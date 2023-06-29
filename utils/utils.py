import os
from web3 import Web3
from solcx import compile_standard

from secrets import token_bytes
from coincurve import PublicKey
from sha3 import keccak_256
import time


def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def generate_keys(private_key="", include_public_key=False):
    if private_key == "":
        private_key = keccak_256(token_bytes(32)).digest()
    else:
        private_key = int(f"0x{private_key}", 16).to_bytes(32, "big")
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    res = {
        "skey": f"{private_key.hex()}",
        "addr": Web3.toChecksumAddress(f"0x{addr.hex()}"),
    }
    if include_public_key:
        res["pub_key"] = public_key.hex()
    return res


def getWeb3(url):
    for i in range(5):
        w3 = Web3(Web3.HTTPProvider(url))
        if not w3.isConnected():
            time.sleep(5)
            print(f"Can not connect to {url}. Retrying {i+1}/5")
        else:
            break
    if not w3.isConnected():
        print("ERROR: Check network connection. ", url)
        raise Exception("ERROR: Check network connection")
    return w3


def setWeb3DefaultAccount(web3, account):
    try:
        web3.eth.default_account = Web3.toChecksumAddress(account)
    except Exception as e:
        print("ERROR: One funded account is necessary to deploy contracts.")
        print(e)
        raise e
    return True


def transact(w3: Web3, userAddr, userKey, contract, method, params, value=0, wait=True):
    if w3.eth.get_code(contract["address"]) == b"":
        print("ERROR: Contract doesn't exist at provided address.")
        return False
    try:
        nonce = w3.eth.get_transaction_count(Web3.toChecksumAddress(userAddr))
        transaction = {"gas": 3000000, "gasPrice": 0, "value": value, "nonce": nonce}
        interface = w3.eth.contract(address=contract["address"], abi=contract["abi"])
        params_string = build_params_string(params)
        s = f"interface.functions.{method}({params_string})\
            .buildTransaction(transaction)"
        contract_transaction = eval(s)

        signed = w3.eth.account.sign_transaction(contract_transaction, userKey)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
        if wait:
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            if tx_receipt["status"] == 0:
                print("Warning: Contract interaction returned status 0.")
                return False
            print("Success!")
            return tx_receipt
        else:
            return tx_hash
    except Exception as e:
        print("Warning:", e)
        return False


def call(w3: Web3, contract, method, params):
    interface = w3.eth.contract(address=contract["address"], abi=contract["abi"])
    if w3.eth.get_code(contract["address"]) == b"":
        print("ERROR: Contract doesn't exist at provided address.")
        return False
    try:
        params_string = build_params_string(params)
        response = eval(f"interface.functions.{method}({params_string}).call()")

        return response
    except Exception as e:
        print("Warning:", e)
        return False


def sendTransaction(
    w3: Web3, senderAddr, senderKey, transaction, silent, wait=True, nonce=None
):
    if not nonce:
        nonce = w3.eth.get_transaction_count(senderAddr)

    transaction["nonce"] = nonce

    # When you run send_raw_transaction, you get back the hash of the transaction:
    try:
        signed = w3.eth.account.sign_transaction(transaction, senderKey)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
        if wait:
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, poll_latency=5)
            if tx_receipt["status"] == 0:
                print("Warning: send receipt status is 0")
                return False
            else:
                return tx_receipt
        else:
            return tx_hash
    except Exception as e:
        print("ERROR: Could not send raw transaction.")
        print(str(e))
        return False

    if not silent:
        print("Transaction sent!")
    return True


def sendLegacyTx(
    w3: Web3,
    senderAddr,
    senderKey,
    receiverAddr,
    amount_to_send,
    chain_id,
    silent,
    wait=True,
    nonce=None,
):
    transaction = {
        "to": receiverAddr,
        "value": amount_to_send,
        "gas": 2000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": nonce,
        "chainId": int(chain_id),
    }
    return sendTransaction(w3, senderAddr, senderKey, transaction, silent, wait, nonce)


def sendEip2930Tx(
    w3: Web3,
    senderAddr,
    senderKey,
    receiverAddr,
    amount_to_send,
    chain_id,
    silent,
    wait=True,
    nonce=None,
):
    transaction = {
        "to": receiverAddr,
        "value": amount_to_send,
        "gas": 2000000,
        "gasPrice": 200,
        "accessList": [],
        "nonce": nonce,
        "chainId": int(chain_id),
    }
    return sendTransaction(w3, senderAddr, senderKey, transaction, silent, wait, nonce)


def sendEip1559Tx(
    w3: Web3,
    senderAddr,
    senderKey,
    receiverAddr,
    amount_to_send,
    chain_id,
    silent,
    wait=True,
    nonce=None,
):
    transaction = {
        "to": receiverAddr,
        "value": amount_to_send,
        "gas": 100000,
        "gasPrice": w3.eth.gas_price,
        "nonce": nonce,
        "chainId": int(chain_id),
    }
    return sendTransaction(w3, senderAddr, senderKey, transaction, silent, wait, nonce)


def send(
    w3: Web3,
    senderAddr,
    senderKey,
    receiverAddr,
    amount_to_send,
    silent,
    wait=True,
    nonce=None,
):
    return sendEip1559Tx(
        w3, senderAddr, senderKey, receiverAddr, amount_to_send, 78, silent, wait, nonce
    )  # TODO: Don't hardcode


def import_account(w3: Web3, userAddr, userKey, passphrase, silent=False):
    # Import recipient account
    # First check if account exists:
    existing_accounts = w3.eth.accounts
    if userAddr not in existing_accounts:
        try:
            w3.geth.personal.import_raw_key(userKey, passphrase)
        except Exception as e:
            print("ERROR: Could not import account key for account ", userAddr)
            print(str(e))
            return False
        if not silent:
            print("Account imported:", userAddr)
    else:
        if not silent:
            print("Account already exists:", userAddr)
    return True


def unlock_account(w3: Web3, userAddr, passphrase, silent=False):
    try:
        w3.geth.personal.unlock_account(
            userAddr, passphrase, 0
        )  # 0 is for indefinite unlock. Might want to lock accounts after test is done
    except Exception as e:
        print("ERROR: Could not unlock account", userAddr)
        print(str(e))
        return False
    if not silent:
        print("Account unlocked.")
    return True


def lock_account(w3: Web3, userAddr, silent=False):
    try:
        w3.geth.personal.lock_account(userAddr)
    except Exception as e:
        print("ERROR: Could not lock account", userAddr)
        print(str(e))
        return 0
    if not silent:
        print("Account locked.")
    return 1


def compileAndDeployContract(
    contractName: str,
    contractFilePath: str,
    additionalPath: str,
    w3: Web3,
    constructorArgs,
    account: str,
    skey: str,
    silent=False,
    withUnlocked=False,
):
    bytecode, abi = compileContract(
        contractName, contractFilePath, additionalPath, w3, silent
    )
    result = deployContract(
        bytecode, abi, w3, constructorArgs, account, skey, silent, withUnlocked
    )
    return result


def compileContract(
    contractName: str,
    contractFilePath: str,
    additionalPath: str,
    w3: Web3,
    silent=False,
):
    prev_path = os.getcwd()
    os.chdir(contractFilePath)
    if not silent:
        print("Compiling contract", contractName, "\b...")
    try:
        # Solidity source code
        contractFileName = contractName + ".sol"
        compiled_sol = compile_standard(
            {
                "language": "Solidity",
                "sources": {
                    contractFileName: {
                        "urls": [
                            contractFilePath
                            + "/"
                            + additionalPath
                            + "/"
                            + contractFileName
                        ]
                    }
                },
                "settings": {
                    "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}
                },
            },
            # solc_version="0.8.6",
            allow_paths=[contractFilePath],
        )

        # get bytecode
        bytecode = compiled_sol["contracts"][contractFileName][contractName]["evm"][
            "bytecode"
        ]["object"]

        # get abi
        abi = compiled_sol["contracts"][contractFileName][contractName]["abi"]

        if not silent:
            print("Contract compiled.")

        return bytecode, abi

    except Exception as e:
        print("ERROR: Could not compile contract.")
        print(e)
        return False, False
    finally:
        os.chdir(prev_path)


def deployContract(
    bytecode,
    abi,
    w3: Web3,
    constructorArgs,
    account,
    skey,
    silent=False,
    withUnlocked=False,
    wait=True,
):
    if not silent:
        print("Deploying contract...")
    try:
        deployer = w3.eth.contract(abi=abi, bytecode=bytecode)
        # List of arguments is deployed to constructor method input.
        # If '' nothing is passed.
        if withUnlocked:
            tx_hash = deployer.constructor(*constructorArgs).transact()
        else:
            nonce = w3.eth.get_transaction_count(account)
            transaction = {
                "gas": 3000000,
                "value": 0,
                "maxFeePerGas": 2000000000,
                "maxPriorityFeePerGas": 1000000000,
                "nonce": nonce,
                "chainId": 78,
            }
            deployment_transaction = deployer.constructor(
                *constructorArgs
            ).buildTransaction(transaction)
            signed = w3.eth.account.sign_transaction(deployment_transaction, skey)
            tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)

        if wait:
            # Wait for the transaction to be mined, and get the transaction receipt
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            if tx_receipt["status"] == 0:
                print("Error: Deploy status is 0")
                return False, False
            if not silent:
                print("Contract deployed!")
            deployedAddr = Web3.toChecksumAddress(tx_receipt.contractAddress)
            return {"abi": abi, "deployedAddr": deployedAddr, "tx_receipt": tx_receipt}
        else:
            return tx_hash.hex()
    except Exception as e:
        print("ERROR: Could not deploy contract.")
        print(e)
        return False, False


def build_params_string(params):
    s = ""
    for p in params:
        if p != params[0]:
            s += ", "
        if type(p) is str:
            s += f'"{p}"'
        else:
            s += f"{p}"
    return s
