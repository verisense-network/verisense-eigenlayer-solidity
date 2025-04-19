const {ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    const verisenseAVSManager = await upgrades.deployProxy(VerisenseAVSManager, [

    ]);
    await  verisenseAVSManager.waitForDeployment();
    console.log("VerisenseAVSManager deployed to:", await verisenseAVSManager.getAddress());
}
main();