const { expect, util } = require("chai");
const { ethers } = require("hardhat");

describe("MultiSig Contract", function () {
    async function deployFixture() {
        const [owner, signer1, signer2, addr1, addr2] = await ethers.getSigners();

        const MultiSig = await ethers.getContractFactory("MultiSig");
        const multiSig = await MultiSig.deploy(signer1.address, signer2.address);
        console.log("MultiSig deployed to:", multiSig.target);
        await multiSig.waitForDeployment();

        const MockERC20 = await ethers.getContractFactory("MockERC20");
        const token = await MockERC20.deploy("TestToken", "TTK", ethers.parseEther("1000"));
        await token.waitForDeployment();
        console.log("MockERC20 deployed to:", token.target);

        return { multiSig, token, owner, signer1, signer2, addr1, addr2 };
    }

    it("Should deploy with correct signers", async function () {
        const { multiSig, signer1, signer2 } = await deployFixture();
        expect(await multiSig.hasRole(await multiSig.SIGNER_ROLE(), signer1.address)).to.be.true;
        expect(await multiSig.hasRole(await multiSig.SIGNER_ROLE(), signer2.address)).to.be.true;
    });

   it("Should execute a withdrawal with valid signatures", async function () {
        const { multiSig, token, signer1, signer2, addr1 } = await deployFixture();
        console.log("This is our addresses: ", signer1.address, signer2.address);
        const tokens = [token.target];
        const amounts = [ethers.parseEther("100")];
        const ethAmount = ethers.parseEther("1");

        await token.mint(multiSig.target, amounts[0]);
        await addr1.sendTransaction({ to: multiSig.target, value: ethAmount });
    ethers.arr
        const withdrawMessageHash = ethers.keccak256(ethers.toUtf8Bytes("WITHDRAWAL"));
        console.log("Withdrawal message hash: ", withdrawMessageHash);
        const signature1 = await signer1.signMessage(ethers.getBytes(withdrawMessageHash));
        const signature2 = await signer2.signMessage(ethers.getBytes(withdrawMessageHash));
        // console.log("Signature1: ", signature1, "Signature2: ", signature2);
        const tx = await multiSig.connect(signer1).withdrawal(tokens, amounts, ethAmount, [signature1, signature2]);

        await expect(tx)
            .to.emit(multiSig, "Withdrawn")
            .withArgs(signer1.address, tokens, amounts, ethAmount);
        
        expect(await token.balanceOf(signer1.address)).to.equal(amounts[0]);
    });

    it("Should reject withdrawal with invalid signatures", async function () {
        const { multiSig, token, signer1, signer2, addr1 } = await deployFixture();

        const tokens = [token.target];
        const amounts = [ethers.parseEther("100")];
        const ethAmount = ethers.parseEther("1");

        await token.mint(multiSig.target, amounts[0]);
        await addr1.sendTransaction({ to: multiSig.target, value: ethAmount });

        const invalidSignature = ethers.randomBytes(65);

        await expect(
            multiSig.connect(signer1).withdrawal(tokens, amounts, ethAmount, [invalidSignature, invalidSignature])
        ).to.be.reverted;;
    });
});
