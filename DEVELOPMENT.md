# Automated Tests for a Cardano Sidechain

This project consists of a collection of tests for a Cardano Sidechain, developed by Input Output Global, along with some utilities and scripts.

## Contents
- models for a local database (transactions), storing the state of the soak tests, and a Class for Burn transaction in folder `models`
- useful scripts in `scripts`
- the tests in folder `tests`
- useful utilities in folder `utils`

### `tests/`

- `RPC_endpoints` : tests the endpoints of nodes. To be run against a specified network (local or remote).
- `bridge_test` : tests the bridge functionality and the connection between the main chain and the sidechain in general. Tests are defined with Cucumber, and are run against a specified main chain and sidechain environment in a corresponding config file. A postgres connection to a dbsync should be established for the sidechain to follow the main chain. The bridge tests verifies connectivity of the components, ability to register and deregister, minimum stake requirement, active flow (sidechain to main chain) and passive flow (main chain to sidechain). Finally there is a soak test, where a number of accounts on both chains interact with random amounts of transfers. Specifically, there are 4 types of transactions: main chain (mc) to mc, sidechain (sc) to sc, mc to sc and sc to mc. The goal is to maintain the original balance after a long period of running this test.


### `scripts/`

* **scripts/fund_account.py:** A useful tool that can fund accounts (using a predefined faucet), import, lock and unlock accounts to a node.

### `utils/`

* **utils/api.py:** A python interface to most RPC endpoint calls to the network.

    _Usage (in a python terminal):_
     ```Python
    from api import *
    e() # Will print a manual of mostly used methods
    ee() # Will print a manual of all methods
    ```
* **utils/cardano_cli.py:** A python wrapper to many cardano-cli commands.

* **utils/log_wrapper.py:** A python wrapper to the logging library.

* **utils/sendTokens.py:** A script that support cardano transactions, including native tokens.

* **utils/utils.py:** Useful library to be imported in tests, or used to interact with the network, with methods such as send, compile_contract and deploy_contract.

### `models/`
 * db/transaction.py
 * sc_evm/burn_tx.py


## Usage

  Start a python virtual environment (recommended version python3.10):
  - python3.10 -m venv venv
  - source venv/bin/activate
  - pip install -r requirements.txt

  ### RPC Test
  pytest tests/RPC_endpoints --network-url="http://127.0.0.1:8545" \
                             --network-name="My_Test_Network" \
                             --network-version=79 \
                             --chain-id=79 \
                             --node-mode="faucet" \
                             --node-number=0 \
                             -k=test_RPC_endpoints.py
    The network name, node-mode and node-number will be used in the fund_accounts script to determine the funding account.
    It can be bypassed with a private key though.

  ### Bridge and Soak Test
  For Bridge and Soak tests, nix is suggested additionally for running the CLIs directly from the public repo. However you can build the binaries and use them instead. For nix installation visit:
  https://github.com/DeterminateSystems/nix-installer#usage
  (Suggested because it automatically sets up the settings for flakes)
  or
  https://nixos.org/download.html
  or if you prefer a docker container:
  https://nixos.org/download.html#nix-install-docker
  Finally a config.json containing the URLs to CTL Server, Ogmios and ogmios-datum-cache is needed at the running directory.
  A sample is provided at `tests/bridge_test/features`

  #### Bridge Test
  behave tests/bridge_test/features \
        --format=pretty \
        --define config_file=PATH_TO/bridge-config.json \
        --include 'features/bridge'

  ##### bridge-config.json
      Most parameters are self explanatory. Some extra tips:
      sc_evm_cli: The path to the sidechain CLI executable can be local but can also be accessed from a remote repo that has a nix flake. E.g.:
      ```
      nix run github:<Github URL>/<Repo name>/<Tag or revision>?.#sc-evm-cli --no-write-lock-file --
      ```
      trustless_ctl_cli: Same as above.
      db_path: The first time the soak test will run a local db will be created at the provided location. It will be used for the subsequent test runs.

  #### Soak Test
  behave tests/bridge_test/features \
        --format=pretty \
        --define config_file=PATH_TO/config.json \
        --include 'features/soak'