import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ignition-ethers";
import "@openzeppelin/hardhat-upgrades";

const {deploy_pri_key} = require("./account.json");
const {mainnet_pri_key} = require("./account.json");

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    holesky: {
      url: `https://ethereum-holesky-rpc.publicnode.com`,
      accounts: [deploy_pri_key],
    },
    mainnet: {
      url: `https://ethereum-rpc.publicnode.com`,
      accounts: [mainnet_pri_key]
    }
  }
};

export default config;
