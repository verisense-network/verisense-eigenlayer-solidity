const { ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    console.log("Upgrading VerisenseAVSManager...");
    const r = await upgrades.upgradeProxy(process.env.PROXY, VerisenseAVSManager);
    console.log("VerisenseAVSManager upgraded successfully address: ", await r.getAddress());
}

main();
