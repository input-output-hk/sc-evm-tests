import json
from subprocess import PIPE, Popen
from os.path import exists
from datetime import datetime
import os
import time
import sys
import utils.log_wrapper as logger

current = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current)


CARDANO_CLI_PATH = ""


class Recipient:
    address = str
    stake_address = str
    lovelace_amount_received = int
    lovelace_amount_to_send = int
    token_amount_to_send = int

    def __init__(self, addr, stake_addr, lovelace_in, lovelace_out, tokens_out):
        self.address = addr
        self.stake_address = stake_addr
        self.lovelace_amount_received = lovelace_in
        self.lovelace_amount_to_send = lovelace_out
        self.token_amount_to_send = tokens_out


def getCardanoCliValue(command, key):
    with Popen(
        CARDANO_CLI_PATH + command, stdout=PIPE, stderr=PIPE, shell=True
    ) as process:
        stdout, stderr = process.communicate()
        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
        if process.returncode != 0:
            raise Exception(f"Error calling {command}")
    if not key == "":
        try:
            result = json.loads(stdout)[key]
            return result
        except Exception as e:
            logger.error(
                f"Request return not in JSON format or key {key} doesn't exist: {e}"
            )
            return -1
    return stdout


def getLovelaceBalance(addr, network="mainnet", onlyAda=False):
    logger.info("Getting address' balance in lovelace...")
    try:
        utxos = getAddrUTxOs(addr, network, onlyAda=onlyAda)
        dict = getTokenListFromTxHash(utxos)
        keys = list(utxos.keys())
        return dict["ADA"], keys
    except Exception as e:
        logger.error(e)
        return -1, []


def getStakeBalance(stake_addr, network="mainnet"):
    command = f"cardano-cli query stake-address-info \
        --cardano-mode --address {stake_addr} --{network}"
    res = eval(getCardanoCliValue(command, ""))
    return res[0]["rewardAccountBalance"]


def getAddrUTxOs(addr, network="mainnet", onlyAda=False):
    logger.info("Getting address transactions...")
    outfile = "utxos.json"
    command = (
        f"cardano-cli query utxo --address {addr} --{network} --out-file {outfile}"
    )
    if getCardanoCliValue(command, "") != -1:
        file = open(outfile)
        utxosJson = json.load(file)
        file.close()
        os.remove(outfile)
        if onlyAda:
            # only return utxo if they contain one token type (ie lovelace)
            return {
                utxo: utxosJson[utxo]
                for utxo in utxosJson
                if len(utxosJson[utxo]["value"].keys()) == 1
            }
        else:
            return utxosJson
    else:
        return False


def getTxInWithLargestTokenAmount(utxosJson, tokenPolicyID):
    tokenMax = 0
    maxTokenTxHash = str
    for key in utxosJson.keys():
        for key2 in utxosJson[key]["value"].keys():
            if key2 == "lovelace":
                continue
            else:
                for key3 in utxosJson[key]["value"][key2].keys():
                    if key2 + "." + key3 == tokenPolicyID:
                        if tokenMax < utxosJson[key]["value"][key2][key3]:
                            tokenMax = utxosJson[key]["value"][key2][key3]
                            maxTokenTxHash = key
    return maxTokenTxHash


def getTokenListFromTxHash(utxosJson):
    logger.info("Getting list of tokens and ADA with amounts...")
    tokensDict = {}
    for key in utxosJson.keys():
        for key2 in utxosJson[key]["value"].keys():
            if key2 == "lovelace":
                if "ADA" in tokensDict.keys():
                    tokensDict["ADA"] += utxosJson[key]["value"][key2]
                else:
                    tokensDict["ADA"] = utxosJson[key]["value"][key2]
            else:
                for key3 in utxosJson[key]["value"][key2].keys():
                    if key2 + "." + key3 in tokensDict.keys():
                        tokensDict[key2 + "." + key3] += utxosJson[key]["value"][key2][
                            key3
                        ]
                    else:
                        tokensDict[key2 + "." + key3] = utxosJson[key]["value"][key2][
                            key3
                        ]
    return tokensDict


def getForeignTokensFromTokenList(tokensDict: dict, tokenPolicyID: str):
    logger.info("Getting list of foreign tokens received with amounts...")
    foreignTokensDict = tokensDict.copy()
    foreignTokensDict.pop("ADA", None)
    foreignTokensDict.pop(tokenPolicyID, None)
    return foreignTokensDict


def getProtocolJson(network="mainnet"):
    if not exists("protocol.json"):
        logger.info("Getting protocol.json...")
        command = f"cardano-cli query protocol-parameters \
            --{network} --out-file protocol.json"
        return getCardanoCliValue(command, "")
    else:
        logger.info("Protocol file found.")
        return


def queryTip(keyword, network="mainnet"):
    logger.info(f"Getting current {keyword}...")
    command = f"cardano-cli query tip --{network}"
    return getCardanoCliValue(command, keyword)


def getMinFee(txInCnt, txOutCnt, network="mainnet"):
    logger.info("Getting min fee for transaction...")
    txOutCnt += 1
    witness_count = 1
    getProtocolJson(network=network)
    command = f"cardano-cli transaction calculate-min-fee \
                                --tx-body-file tx.tmp \
                                --tx-in-count {txInCnt} \
                                --tx-out-count {txOutCnt} \
                                --{network} \
                                --witness-count {witness_count} \
                                --byron-witness-count 0 \
                                --protocol-params-file protocol.json"
    feeString = getCardanoCliValue(command, "")
    return int(feeString.split(" ")[0])


def getDraftTX(txInList, returnAddr, recipientList, ttlSlot):
    logger.info("Creating tx.tmp...")
    command = "cardano-cli transaction build-raw \
               --fee 0 "
    for txIn in txInList:
        command += f"--tx-in {txIn} "
    # The recipient is of class Recipient
    # (address, lovelace in, lovelace out, token out)
    for recipient in recipientList:
        command += f"--tx-out {recipient.address}+0 "
    command += f"--tx-out {returnAddr}+0 \
                 --invalid-hereafter {ttlSlot} \
                 --out-file tx.tmp"
    getCardanoCliValue(command, "")
    return


def getDraftTXSimple(txInList, returnAddr, recipientAddr, ttlSlot):
    logger.info("Creating simple tx.tmp...")
    command = "cardano-cli transaction build-raw \
               --fee 0 "
    for txIn in txInList:
        command += f"--tx-in {txIn} "
    command += f"--tx-out {recipientAddr}+0 "
    command += f"--tx-out {returnAddr}+0 \
                 --invalid-hereafter {ttlSlot} \
                 --out-file tx.tmp"
    getCardanoCliValue(command, "")
    return


def getRawTxSimple(
    txInList,
    returnAddr,
    recipientAddr,
    lovelace_amount,
    ttlSlot,
    network,
    era="babbage-era",
):
    logger.info("Creating simple tx.raw...")
    command = f"cardano-cli transaction build --{era} --{network} "
    for txIn in txInList:
        command += f"--tx-in {txIn} "
    command += f"--tx-out {recipientAddr}+{lovelace_amount} "
    command += f"--change-address {returnAddr} "
    command += f"--invalid-hereafter {ttlSlot} \
                 --out-file tx.raw"
    getCardanoCliValue(command, "")


def getRawTx(
    txInList,
    initLovelace,
    initToken,
    returnAddr,
    recipientList,
    ttlSlot,
    fee,
    minFee,
    tokenPolicyId,
    foreignTokensDict,
):
    logger.info("Creating tx.raw...")
    lovelace_received = 0
    lovelace_to_send = 0
    tokens_to_send = 0
    fees_withheld = 0
    # The recipient is of class Recipient
    # (address, lovelace in, lovelace out, token out)
    for recipient in recipientList:
        lovelace_received += recipient.lovelace_amount_received
        lovelace_to_send += recipient.lovelace_amount_to_send
        tokens_to_send += recipient.token_amount_to_send
        fees_withheld += minFee

    lovelace_to_return = initLovelace - fee - lovelace_to_send
    tokens_to_return = initToken - tokens_to_send
    command = f"cardano-cli transaction build-raw \
                --fee {fee} "
    for txIn in txInList:
        command += f"--tx-in {txIn} "
    for recipient in recipientList:
        command += f'--tx-out {recipient.address}+{recipient.lovelace_amount_to_send}\
            +"{recipient.token_amount_to_send} {tokenPolicyId}" '
    command += f'--tx-out {returnAddr}+{lovelace_to_return}\
        +"{tokens_to_return} {tokenPolicyId}"'
    for key in foreignTokensDict:  # Send all other incoming tokens too
        command += f'+"{foreignTokensDict[key]} {key}"'
    command += f" --invalid-hereafter {ttlSlot} \
                 --out-file tx.raw"
    getCardanoCliValue(command, "")


def signTx(signingKeyFileList, network="mainnet", filename="tx"):
    logger.info("Signing Transaction...")
    command = "cardano-cli transaction sign "
    for key in signingKeyFileList:
        command += f"--signing-key-file {key} "
    command += f"--tx-body-file {filename}.raw \
                 --out-file {filename}.signed \
                 --{network}"
    getCardanoCliValue(command, "")


def submitSignedTx(signed_file="tx", network="mainnet"):
    logger.info("Submitting Transaction...")
    command = (
        f"cardano-cli transaction submit --tx-file {signed_file}.signed --{network}"
    )
    return getCardanoCliValue(command, "")


def sendTokenToAddr(
    myPaymentAddrSignKeyFile: str,
    txInList: list,
    initLovelace: int,
    initToken: int,
    fromAddr: str,
    recipientList: list,
    tokenPolicyId: str,
    minFee: int,
    foreignTokensDict: dict,
    network="mainnet",
):
    ttlSlot = queryTip("slot", network) + 2000
    getDraftTX(txInList, fromAddr, recipientList, ttlSlot)
    fee = getMinFee(len(txInList), len(recipientList), network=network)
    getRawTx(
        txInList,
        initLovelace,
        initToken,
        fromAddr,
        recipientList,
        ttlSlot,
        fee,
        minFee,
        tokenPolicyId,
        foreignTokensDict,
    )
    signTx([myPaymentAddrSignKeyFile], network=network)
    return submitSignedTx(network=network)


def waitForTxReceipt(paymentAddr, tokenPolicyId, myTxHash, utxosOld, network="mainnet"):
    # logger.info the current time to estimate how long it will take
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    logger.info("Transaction submitted at " + current_time + ".")
    logger.info("Waiting for a block to include the transaction...")
    utxosNew = utxosOld

    while utxosNew == utxosOld:
        time.sleep(10)
        logger.info("Polling for new Txs")
        utxosNew = getAddrUTxOs(paymentAddr, network=network)

    myTxHashNew = getTxInWithLargestTokenAmount(utxosNew, tokenPolicyId)
    if myTxHash != myTxHashNew:
        logger.info(f"Transaction submitted at {current_time}.")
        return True


def getRawTxStakeWithdraw(tx_in, payment_addr, stake_addr):
    command = f"cardano-cli transaction build-raw \
                --tx-in {tx_in} \
                --tx-out {payment_addr}+0 \
                --withdrawal {stake_addr}+0 \
                --invalid-hereafter 0 \
                --fee 0 \
                --out-file tx.tmp"
    getCardanoCliValue(command, "")


def buildRawTxStakeWithdraw(
    tx_in,
    payment_addr,
    withdrawal,
    stake_addr,
    stake_rewards,
    minFee,
    network="mainnet",
):
    currentSlot = queryTip("slot", network)
    command = f"cardano-cli transaction build-raw \
                --tx-in {tx_in} \
                --tx-out {payment_addr}+{withdrawal} \
                --withdrawal {stake_addr}+{stake_rewards} \
                --invalid-hereafter {currentSlot+1000} \
                --fee {minFee} \
                --out-file withdraw_rewards.raw"
    getCardanoCliValue(command, "")


def generateKESkeys():
    logger.info("Generating new KES keys...")
    command = "cardano-cli node key-gen-KES \
              --verification-key-file kes.vkey \
              --signing-key-file kes.skey"
    getCardanoCliValue(command, "")


def generatePaymentKeyPair():
    logger.info("Generating payment key pair...")
    command = "cardano-cli address key-gen \
               --verification-key-file payment.vkey \
               --signing-key-file payment.skey"
    getCardanoCliValue(command, "")


def getSlotsPerKESPeriod(
    genesisFile="/opt/cardano/cnode/files/mainnet-shelley-genesis.json",
):
    if not exists(genesisFile):
        logger.error("ERROR: genesis.json file does not exist.")
        return False
    with open(genesisFile) as genesis:
        data = json.load(genesis)
        try:
            KESPeriod = data["slotsPerKESPeriod"]
            return KESPeriod
        except Exception as e:
            logger.error(f"File is not formatted correctly: {e}")


def generateStakeKeyPair():
    logger.info("Generating stake key pair...")
    command = "cardano-cli stake-address key-gen \
               --verification-key-file stake.vkey \
               --signing-key-file stake.skey"
    getCardanoCliValue(command, "")


def generatePaymentAddress(network="mainnet"):
    logger.info(f"Generating payment address for {network}")
    command = f"cardano-cli address build \
                --payment-verification-key-file payment.vkey \
                --out-file payment.addr \
                --{network}"
    getCardanoCliValue(command, "")


def generatePaymentAddressForStaking(network="mainnet"):
    logger.info(f"Generating payment address for {network}")
    command = f"cardano-cli address build \
                --payment-verification-key-file payment.vkey \
                --stake-verification-key-file stake.vkey \
                --out-file payment.addr \
                --{network}"
    getCardanoCliValue(command, "")


def generateStakeAddress(network="mainnet"):
    logger.info(f"Generating stake address for {network}")
    command = f"cardano-cli stake-address build \
                --stake-verification-key-file stake.vkey \
                --out-file stake.addr \
                --{network}"
    getCardanoCliValue(command, "")


def createRegistrationCertificate():
    logger.info("Creating registration certificate")
    command = "cardano-cli stake-address registration-certificate \
                --stake-verification-key-file stake.vkey \
                --out-file stake.cert"
    getCardanoCliValue(command, "")


def buildRegisterCertTx(
    utxos, TTL, amount="1000000", network="mainnet", era="babbage-era"
):
    logger.info("Building raw Tx for Registering Stake certificate")
    txIns = " ".join([f"--tx-in {utxo}" for utxo in utxos])
    command = f"cardano-cli transaction build \
                --{era} \
                {txIns} \
                --tx-out $(cat payment.addr)+{amount} \
                --change-address $(cat payment.addr) \
                --{network}  \
                --out-file tx.raw \
                --certificate-file stake.cert \
                --invalid-hereafter {TTL} \
                --witness-override 2"
    getCardanoCliValue(command, "")


def generateVRFKeyPair():
    logger.info("Generating VRF key pair")
    command = "cardano-cli node key-gen-VRF \
                --verification-key-file vrf.vkey \
                --signing-key-file vrf.skey"
    getCardanoCliValue(command, "")


def generateColdKeys():
    logger.info("Generating cold keys")
    command = "cardano-cli node key-gen \
                --cold-verification-key-file cold.vkey \
                --cold-signing-key-file cold.skey \
                --operational-certificate-issue-counter-file cold.counter"
    getCardanoCliValue(command, "")


def generateKESKeyPair():
    logger.info("Generating KES key pair")
    command = "cardano-cli node key-gen-KES \
                --verification-key-file kes.vkey \
                --signing-key-file kes.skey"
    getCardanoCliValue(command, "")


def generateOperationalCertificate(
    kes_vkey="kes.vkey",
    cold_skey="cold.skey",
    cold_counter="cold.counter",
    slotsPerKESPeriod=129600,
    network="mainnet",
):
    logger.info("Generating operational certificate")
    currentTip = queryTip("slot", network)
    assert type(currentTip) == int, "currentTip is not an integer"
    assert currentTip > 0, "current tip is not a positive number"

    currentKESPeriod = int(currentTip / slotsPerKESPeriod)
    command = f"cardano-cli node issue-op-cert \
                --kes-verification-key-file {kes_vkey} \
                --cold-signing-key-file {cold_skey} \
                --operational-certificate-issue-counter {cold_counter} \
                --kes-period {currentKESPeriod} \
                --out-file node.cert"
    return getCardanoCliValue(command, "") != -1


def getHashOfMetadataJSON(file):
    command = f"cardano-cli stake-pool metadata-hash --pool-metadata-file {file}"
    hashValue = getCardanoCliValue(command, "")
    return hashValue


def generateStakePoolRegistrationCertificate(
    pledge,
    pool_ip,
    metadata_url,
    metadata_hash,
    pool_cost=340000000,
    pool_margin=0,
    network="mainnet",
    pool_port=3533,
):
    logger.info("Generating stake pool registration certificate")
    command = f"cardano-cli stake-pool registration-certificate \
                --cold-verification-key-file cold.vkey \
                --vrf-verification-key-file vrf.vkey \
                --pool-pledge {pledge} \
                --pool-cost {pool_cost} \
                --pool-margin {pool_margin} \
                --pool-reward-account-verification-key-file stake.vkey \
                --pool-owner-stake-verification-key-file stake.vkey \
                --{network} \
                --pool-relay-ipv4 {pool_ip} \
                --pool-relay-port {pool_port} \
                --metadata-url {metadata_url} \
                --metadata-hash {metadata_hash} \
                --out-file pool-registration.cert"
    getCardanoCliValue(command, "")


def generateDelegationCertificatePledge():
    logger.info("Generating delegation certificate pledge")
    command = "cardano-cli stake-address delegation-certificate \
                --stake-verification-key-file stake.vkey \
                --cold-verification-key-file cold.vkey \
                --out-file delegation.cert"
    getCardanoCliValue(command, "")


def buildPoolAndDelegationCertTx(
    utxos, TTL, amount="1000000", network="mainnet", era="babbage-era"
):
    logger.info("Building Tx for generating pool and delegation certificate")
    txIns = " ".join([f"--tx-in {utxo}" for utxo in utxos])
    command = f"cardano-cli transaction build \
                --{era} \
                --{network} \
                --witness-override 3 \
                {txIns} \
                --tx-out $(cat payment.addr)+{amount} \
                --change-address $(cat payment.addr) \
                --invalid-hereafter {TTL} \
                --certificate-file pool-registration.cert \
                --certificate-file delegation.cert \
                --out-file tx.raw"
    getCardanoCliValue(command, "")


def getPoolId():
    logger.info("Getting pool ID")
    command = 'cardano-cli stake-pool id \
        --cold-verification-key-file cold.vkey --output-format "hex"'
    return getCardanoCliValue(command, "")


def verifyPoolIsRegistered(poolId, network="mainnet"):
    logger.info(f"Verifying that pool {poolId} is registered...")
    command = (
        f"cardano-cli query ledger-state --{network} | grep publicKey | grep {poolId}"
    )
    pubKey = getCardanoCliValue(command, "")
    if "publicKey" in pubKey and poolId in pubKey:
        return True
    else:
        return False


def buildSendTokensToOneDestinationTx(
    txInList,
    change_address,
    TTL,
    destination,
    lovelace_amount_to_send,
    sendDict,
    returnDict,
    network="mainnet",
    era="babbage-era",
):
    logger.info("Building raw Tx for Sending multiple tokens")
    command_build = f"cardano-cli transaction build \
                    --{era} \
                    --witness-override 2 "
    i = 1
    for txIn in txInList:
        i = i + 1
        if i < 400:  # Make sure it fits in one tx
            command_build += f"--tx-in {txIn} "
    command_tx_out_destination = f"--tx-out {destination}+"
    command_tokens_destination = ""
    for token in sendDict:
        command_tokens_destination += f'+"{sendDict[token]} {token}"'
    if lovelace_amount_to_send == 0:
        lovelace_amount_to_send = getMinRequiredUtxo(
            era, command_tx_out_destination + "0" + command_tokens_destination
        )
    else:
        lovelace_amount_to_send = str(lovelace_amount_to_send)

    command_return_lovelace = ""
    if len(returnDict) > 1:
        command_return_lovelace = f" --tx-out {change_address}+"
    command_return_tokens = ""
    for token in returnDict:
        if returnDict[token] != 0 and token != "ADA":
            command_return_tokens += f'+"{returnDict[token]} {token}"'

    lovelace_for_txout_return_tokens = ""
    if len(returnDict) > 1:
        lovelace_for_txout_return_tokens = getMinRequiredUtxo(
            era, command_return_lovelace + "0" + command_return_tokens
        )

    command_change_address = f" --change-address {change_address} \
                --{network}  \
                --out-file tx.raw \
                --invalid-hereafter {TTL}"
    command = (
        command_build
        + command_tx_out_destination
        + lovelace_amount_to_send
        + command_tokens_destination
        + command_return_lovelace
        + lovelace_for_txout_return_tokens
        + command_return_tokens
        + command_change_address
    )
    logger.info(command)
    getCardanoCliValue(command, "")


def buildMintTokensTx(
    network,
    era,
    txIn,
    change_address,
    destination_addr,
    lovelace_amount,
    token_amount,
    token_policy_id,
    policy_script_file,
):
    command = f'cardano-cli transaction build \
                --{era} \
                --{network} \
                --witness-override 2 \
                --tx-in {txIn} \
                --tx-out {destination_addr}+{lovelace_amount}+\
                    "{token_amount} {token_policy_id}" \
                --change-address {change_address} \
                --mint="{token_amount} {token_policy_id}" \
                --minting-script-file {policy_script_file} \
                --out-file tx.raw'
    getCardanoCliValue(command, "")


def getSenderAddressFromSimpleTxHash(txHash_txIx: str, network):
    try:
        txHash = txHash_txIx.split("#")[0]  # Drop the TxId
        txIx = txHash_txIx.split("#")[1]  # Drop the TxHash
        txIx = 1 + int(txIx)
    except Exception as e:
        logger.error("ERROR:", e)
        return False
    command = f"cardano-cli query utxo \
                --tx-in {txHash}#{txIx} \
                --{network} \
                --out-file rec_utxos.json && cat rec_utxos.json | jq '.[].address' "
    return getCardanoCliValue(command, "")


def getMinRequiredUtxo(era, txout):
    logger.info("Getting min required amount of lovelace for tx-out...")
    getProtocolJson(network="testnet-magic 7")
    command = f"cardano-cli transaction calculate-min-required-utxo \
                --protocol-params-file protocol.json \
                --{era} \
                {txout}"
    lovelace_value = getCardanoCliValue(command, "")
    assert lovelace_value.startswith(
        "Lovelace"
    ), "ERROR: getMinRequiredUtxo did not return Lovelace and amount"
    lovelace_value = lovelace_value.replace("Lovelace ", "").strip()
    try:
        int(lovelace_value)
    except Exception as e:
        assert (
            False
        ), f"ERROR: could not get integer for lovelace amount \
            from getMinRequiredUtxo: {e}"
    return lovelace_value


def getDelegatedStakeToPool(poolID, network="mainnet"):
    """
    The return of this command will be a json string for the total stake
    of the network and the pool stake.
    MARK is the last snapshot (taken at the last epoch transition) and is not used\
    on the current epoch, it will become SET on the next epoch.
    SET is used in the current epoch for Slot leader election process (block production)
    GO is used in the current epoch for rewards calculation
    """
    logger.info(f"Getting stake delegated to {poolID}...")
    command = f"cardano-cli query stake-snapshot \
                --{network} \
                --stake-pool-id {poolID}"
    return getCardanoCliValue(command, "")
