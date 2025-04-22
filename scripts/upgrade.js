const { ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    console.log("Upgrading VerisenseAVSManager...");
    const r = await upgrades.upgradeProxy("0xCfa255edFB64F5BD149b8CF852b4262B36fCd809", VerisenseAVSManager);
    console.log("VerisenseAVSManager upgraded successfully address: ", await r.getAddress());
}

main();
