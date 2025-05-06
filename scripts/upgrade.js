const { ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    console.log("Upgrading VerisenseAVSManager...");
    const r = await upgrades.upgradeProxy("0x2ad2e6287725e747cB6D4C0d6127Ef1BB55a406E", VerisenseAVSManager);
    console.log("VerisenseAVSManager upgraded successfully address: ", await r.getAddress());
}

main();
