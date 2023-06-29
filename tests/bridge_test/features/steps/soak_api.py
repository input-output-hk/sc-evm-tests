from utils import cardano_cli
import utils.log_wrapper as logger
import os


def parseConfig(confDict):
    try:
        sidechain_node1 = confDict["bridge"]["sidechain_node1"]
        if not sidechain_node1.startswith("http"):
            confDict["bridge"]["sidechain_node1"] = "http://" + os.getenv(
                sidechain_node1
            )
        return confDict["bridge"], confDict["CTL"], True
    except Exception as e:
        logger.error(f"JSON key not found: {e}")
        return None, None, False


def getSCTokenBalanceListOnMC(context, NUMBER_OF_ACCOUNTS):
    sc_token_on_mc_balance_list = []
    total_sc_token_balance = 0
    total_lovelace_balance = 0
    for i in range(NUMBER_OF_ACCOUNTS):
        utxos = cardano_cli.getAddrUTxOs(
            context.mainchain_accounts[i], context.bridge_params["mainchain_network"]
        )
        assert (
            utxos is not False
        ), f"ERROR: Could not get UTxOs of address {context.mainchain_accounts[i]}"
        tokensDict = cardano_cli.getTokenListFromTxHash(utxos)
        if context.bridge_params["mc_sc_token_policy_id"] in tokensDict.keys():
            sc_token_on_mc_amount = tokensDict[
                context.bridge_params["mc_sc_token_policy_id"]
            ]
        else:
            sc_token_on_mc_amount = 0
        if "ADA" in tokensDict.keys():
            lovelace = tokensDict["ADA"]
        else:
            lovelace = 0
        assert (
            type(sc_token_on_mc_amount) == int
        ), "ERROR: Sidechain token balance is not an integer"
        assert type(lovelace) == int, "ERROR: Lovelace balance is not an integer"
        sc_token_on_mc_balance_list.append(sc_token_on_mc_amount)
        total_sc_token_balance += sc_token_on_mc_amount
        total_lovelace_balance += lovelace
    return sc_token_on_mc_balance_list, total_sc_token_balance, total_lovelace_balance


def getSCTokenBalanceList(context, number_of_accounts):
    sc_balance_list = []
    total_balance = 0
    for i in range(number_of_accounts):
        sc_balance = int(
            context.ethRPC.eth_getBalance(
                context.sidechain_accounts[i]["addr"], "latest"
            ).__str__(),
            16,
        )
        total_balance += sc_balance
        sc_balance_list.append(sc_balance)
    return sc_balance_list, total_balance
