const { ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    console.log("Upgrading VerisenseAVSManager...");
    const r = await upgrades.upgradeProxy("0x902038d2D5278dd6504C135FFA49bf635D475f7e", VerisenseAVSManager);
    console.log("VerisenseAVSManager upgraded successfully address: ", await r.getAddress());
}

main();
