const {ethers, upgrades } = require("hardhat");

async function main() {
    const VerisenseAVSManager = await ethers.getContractFactory("VerisenseAVSManager");
    const verisenseAVSManager = await upgrades.deployProxy(VerisenseAVSManager, [
        "0x30770d7E3e71112d7A6b7259542D1f680a70e315",
        "0xA44151489861Fe9e3055d95adC98FbD462B948e7",
        "0x055733000064333CaDDbC92763c58BF0192fFeBf",
        "0xAcc1fb458a1317E886dB376Fc8141540537E68fE",
        86400
    ]);
    await  verisenseAVSManager.waitForDeployment();
    console.log("VerisenseAVSManager deployed to:", await verisenseAVSManager.getAddress());
}
main();

