const {ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    const verisenseAVSManager = await upgrades.deployProxy(VerisenseAVSManager, [
        "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338",
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A",
        "0x135dda560e946695d6f155dacafc6f1f25c1f5af",
        "0x7750d328b314EfFa365A0402CcfD489B80B0adda",
        86400
    ]);
    await  verisenseAVSManager.waitForDeployment();
    console.log("VerisenseAVSManager deployed to:", await verisenseAVSManager.getAddress());
}
main();