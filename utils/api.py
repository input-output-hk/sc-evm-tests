import requests
import json
import re


def e():
    print("###")

    print("start")
    print('n = Node("http://localhost:8540")')
    print("print(n.net_version())")
    print("print(n.healthcheck())")
    print("\n###")
    print("txs")
    print('pretty(n.eth_getTransactionReceipt("stuff"))')
    print('print(n.eth_getTransactionReceipt("stuff"))')
    print(
        'print(n.personal_unlockAccount(\
            "0xbc5ae53a2a79634c1813f3f93e9a5a823ac30d37", "rrrrrrr"))'
    )
    print("print(n.eth_accounts())")

    print("personal")
    print('print(n.personal_importRawKey("priv_key_with_no_0x", "password"))')
    print(
        'print(n.personal_unlockAccount(\
            "0xbc5ae53a2a79634c1813f3f93e9a5a823ac30d37", "rrrrrrr"))'
    )
    print("print(n.eth_accounts())")

    print("###")
    print("accounts")
    print(
        'print(n.eth_getBalance(\
            "0xbc5ae53a2a79634c1813f3f93e9a5a823ac30d37", "latest"))'
    )
    print(
        'print(n.eth_getTransactionCount(\
            "0xbc5ae53a2a79634c1813f3f93e9a5a823ac30d37", "latest"))'
    )
    print('print(n.faucet_sendFunds("0xbc5ae53a2a79634c1813f3f93e9a5a823ac30d37"))')
    print("print(n.faucet_status())")


def ee():
    print("lastCommonBlock(port1, port2)")
    print("balances(addr)")

    print('n = Node("http://localhost:8540")')
    print("print(n.net_version())")
    print("print(n.eth_chainId())")
    print("print(n.healthcheck())")
    print("print(n.faucet_sendFunds(address))")
    print("print(n.faucet_status())")
    print("print(n.eth_gasPrice())")
    print("print(n.eth_getBlockByNumber(block_number, hydrated_transactions=True))")
    print("print(n.eth_getBlockByHash(block_hash, hydrated_transactions=True))")
    print("print(n.eth_getTransactionReceipt(tx_hash=None))")
    print('print(n.eth_getBalance(address, block="latest"))')
    print("print(n.eth_getBlockTransactionCountByHash(block_hash))")
    print("print(n.eth_getBlockTransactionCountByNumber(block_number))")
    print("print(n.eth_blockNumber())")
    print("print(n.eth_getTransactionCount(address, block))")
    print("print(n.eth_getTransactionByHash(tx_hash))")
    print("print(n.personal_sign(message, address, password))")
    print("print(n.eth_accounts())")
    print("print(n.personal_listAccounts())")
    print("print(n.personal_lockAccount(account))")
    print("print(n.personal_newAccount(passphrase))")
    print("print(n.personal_unlockAccount(address, passphrase, duration=0))")
    print("print(n.personal_sendTransaction(tx_string, passphrase))")
    print("print(n.personal_sendTransactionString(tx_string, passphrase))")
    print("print(n.eth_sendTransaction(tx))")
    print("print(n.personal_importRawKey(key, passphrase))")
    print("print(n.eth_sendRawTransaction(tx))")
    print("print(n.eth_getCode(address, block))")
    print("print(n.eth_call(tx, block))")
    print("print(n.eth_getStorageAt(address, quantity, block))")
    print("print(n.eth_estimateGas(tx, block))")
    print("print(n.eth_getLogs(address_json))")

    print("###")
    print("bridge")
    print("print(n.sidechain_getMainchainStatus())")
    print("print(n.sidechain_getStatus())")
    print("print(n.sidechain_getCommittee(epochNum))")
    print('print(n.sidechain_getCandidates("latest"))')
    print('print(n.sidechain_getCurrentCandidates("latest"))')
    print("print(n.sidechain_getPendingTransactions())")
    print("print(n.sidechain_getEpochSignatures(epochNum)")
    print("print(n.sidechain_getOutgoingTransactions(epochNum)")
    print("print(n.sidechain_getOutgoingTxMerkleProof(epochNum, txIndex)")
    print("print(n.sidechain_getSignaturesToUpload(maxEpochs)")


def pretty(input):
    print(json.dumps(json.loads(re.sub("'", '"', str(input))), indent=4))


class EthResult:
    def __init__(self, json_string):
        try:
            self.jsonResponse = json.loads(json_string)
        except Exception:
            raise Exception(f"Couldn't parse json: {json_string}")

    def __str__(self):
        if "result" in self.jsonResponse:
            return str(self.jsonResponse["result"])
        else:
            return str(self.jsonResponse["error"])

    def __getitem__(self, key):
        if "result" in self.jsonResponse:
            return self.jsonResponse["result"][key]
        else:
            return self.jsonResponse["error"][key]

    def isError(self):
        return "result" not in self.jsonResponse


class Node:
    def __init__(self, url, _id=209379124283377):
        self.url = url
        self.id = _id

    def request(self, method, params):
        headers = {"Content-type": "application/json"}
        req = json.dumps(
            {"id": self.id, "jsonrpc": "2.0", "method": method, "params": params}
        )
        return requests.post(self.url, data=req, headers=headers).text

    def check_connection(self):
        try:
            self.net_version()
            return True
        except Exception as e:
            print(e)
            return False

    def faucet_sendFunds(self, addr):
        return EthResult(self.request("faucet_sendFunds", []))

    def evmsidechain_getNetworkInfo(self):
        return EthResult(self.request("evmsidechain_getNetworkInfo", []))

    def healthcheck(self):
        return requests.get(f"{self.url}/healthcheck").text

    def net_version(self):
        return EthResult(self.request("net_version", []))

    def eth_chainId(self):
        return EthResult(self.request("eth_chainId", []))

    def faucet_sendFunds(self, address):
        return EthResult(self.request("faucet_sendFunds", [address]))

    def faucet_status(self):
        return EthResult(self.request("faucet_status", []))

    def eth_gasPrice(self):
        return EthResult(self.request("eth_gasPrice", []))

    def eth_getBlockByNumber(self, block_number, hydrated_transactions=True):
        return EthResult(
            self.request("eth_getBlockByNumber", [block_number, hydrated_transactions])
        )

    def eth_getBlockByHash(self, block_hash, hydrated_transactions=True):
        return EthResult(
            self.request("eth_getBlockByHash", [block_hash, hydrated_transactions])
        )

    def eth_getTransactionReceipt(self, tx_hash=None):
        if tx_hash:
            return EthResult(self.request("eth_getTransactionReceipt", [tx_hash]))
        return EthResult(self.request("eth_getTransactionReceipt", []))

    def eth_getBalance(self, address, block="latest"):
        return EthResult(self.request("eth_getBalance", [address, block]))

    def eth_getBlockTransactionCountByHash(self, block_hash):
        return EthResult(
            self.request("eth_getBlockTransactionCountByHash", [block_hash])
        )

    def eth_getBlockTransactionCountByNumber(self, block_number):
        return EthResult(
            self.request("eth_getBlockTransactionCountByNumber", [block_number])
        )

    def eth_blockNumber():
        return False

    def eth_getTransactionCount(self, address, block):
        return EthResult(self.request("eth_getTransactionCount", [address, block]))

    def eth_getTransactionByHash(self, tx_hash):
        return EthResult(self.request("eth_getTransactionByHash", [tx_hash]))

    def personal_sign(self, message, address, password):
        return EthResult(self.request("personal_sign", [message, address, password]))

    def personal_ecRecover(self, message, signature):
        return EthResult(self.request("personal_ecRecover", [message, signature]))

    def eth_accounts(self):
        return EthResult(self.request("eth_accounts", []))

    def personal_listAccounts(self):
        return EthResult(self.request("personal_listAccounts", []))

    def personal_lockAccount(self, account):
        return EthResult(self.request("personal_lockAccount", [account]))

    def personal_newAccount(self, passphrase):
        return EthResult(self.request("personal_newAccount", [passphrase]))

    def personal_unlockAccount(self, address, passphrase, duration=0):
        return EthResult(
            self.request("personal_unlockAccount", [address, passphrase, duration])
        )

    def personal_sendTransaction(self, tx_string, passphrase):
        tx = json.loads(tx_string)
        return EthResult(self.request("personal_sendTransaction", [tx, passphrase]))

    def personal_sendTransactionString(self, tx_string, passphrase):
        tx = json.loads(tx_string)
        return self.personal_sendTransaction(tx, passphrase)

    def eth_sendTransaction(self, tx):
        return EthResult(self.request("eth_sendTransaction", [tx]))

    def personal_importRawKey(self, key, passphrase):
        return EthResult(self.request("personal_importRawKey", [key, passphrase]))

    def eth_sendRawTransaction(self, tx):
        return EthResult(self.request("eth_sendRawTransaction", [tx]))

    def eth_getCode(self, address, block):
        return EthResult(self.request("eth_getCode", [address, block]))

    def eth_call(self, tx, block):
        return EthResult(self.request("eth_call", [tx, block]))

    def eth_getStorageAt(self, address, quantity, block):
        return EthResult(self.request("eth_getStorageAt", [address, quantity, block]))

    def eth_estimateGas(self, tx, block):
        return EthResult(self.request("eth_estimateGas", [tx, block]))

    def eth_getLogs(self, address):
        return EthResult(self.request("eth_getLogs", [address]))

    # Sidechain RPCs
    def sidechain_getCommittee(self, epochNum):
        return EthResult(self.request("sidechain_getCommittee", [epochNum]))

    def sidechain_getCandidates(self, epochNum):
        return EthResult(self.request("sidechain_getCandidates", [epochNum]))

    def sidechain_getCurrentCandidates(self):
        return EthResult(self.request("sidechain_getCurrentCandidates", []))

    def sidechain_getStatus(self):
        return EthResult(self.request("sidechain_getStatus", []))

    def sidechain_getPendingTransactions(self):
        return EthResult(self.request("sidechain_getPendingTransactions", []))

    def sidechain_getEpochSignatures(self, epochNum):
        return EthResult(self.request("sidechain_getEpochSignatures", [epochNum]))

    def sidechain_getOutgoingTransactions(self, epochNum):
        return EthResult(self.request("sidechain_getOutgoingTransactions", [epochNum]))

    def sidechain_getOutgoingTxMerkleProof(self, epochNum, txIndex):
        return EthResult(
            self.request("sidechain_getOutgoingTxMerkleProof", [epochNum, txIndex])
        )

    def sidechain_getSignaturesToUpload(self, maxEpochs):
        return EthResult(self.request("sidechain_getSignaturesToUpload", [maxEpochs]))

    def sidechain_getMainchainStatus(self):
        return EthResult(self.request("sidechain_getMainchainStatus", []))

        # txpool

    def txpool_content(self):
        return EthResult(self.request("txpool_content", []))

    # SC_EVM RPC extensions
    def evmsidechain_getBlockByNumber(self, block_number, hydrated_transactions=True):
        return EthResult(
            self.request(
                "evmsidechain_getBlockByNumber", [block_number, hydrated_transactions]
            )
        )

    # Generic
    def send(self):
        from_ = input("from1:")
        from_2 = input("from2:")
        to_ = input("to:")
        value = input("to:")

        nonce = self.eth_getTransactionCount(from_, "latest")
        tx = {
            "from": from_,
            "nonce": nonce.__str__(),
            "to": to_,
            "value": int(value) * 10**18,
            "gas": 2 * 10**6,
            "gasPrice": 0,
        }

        tx_string = json.dumps(tx)
        print(
            self.eth_sendRawTransaction(
                self.personal_sign(tx_string, from_2, "rrrrrrr").__str__()
            )
        )


def balances(addr):
    ports = ["8546", "8547", "8548"]
    print("########")
    for p in ports:
        n = Node(f"http://localhost:{p}")
        b = int(str(n.eth_getBalance(addr)), 16)
        print(f"{p} -\t{b}")


def lastCommonBlock(port1, port2):
    n1 = Node(f"http://localhost:{port1}")
    n2 = Node(f"http://localhost:{port2}")
    b1_no = int(n1.eth_getBlockByNumber("latest")["number"], 16)
    b2_no = int(n2.eth_getBlockByNumber("latest")["number"], 16)

    no = min(b1_no, b2_no)

    while True:
        print(f"checking: {no}")
        b1 = n1.eth_getBlockByNumber(hex(no))
        b2 = n2.eth_getBlockByNumber(hex(no))
        if b1["hash"] == b2["hash"]:
            print(f"Last common block : {b1['number']}")
            break
        no = no - 1
        if no < 0:
            print("No common block between those chains")
            break
