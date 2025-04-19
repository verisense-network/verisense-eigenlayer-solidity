
const { ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    console.log("recreate network file ...");
    const r = await upgrades.forceImport(process.env.PROXY, VerisenseAVSManager);
    console.log("Verisense upgraded successfully address: ", await r.getAddress());
}

main();