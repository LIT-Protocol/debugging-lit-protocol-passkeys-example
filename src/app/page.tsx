"use client";
import { LitAbility, LitActionResource } from '@lit-protocol/auth-helpers';
import React, { useState, useEffect } from "react";
import { ethers } from "ethers";

import {
  EthWalletProvider,
  GoogleProvider,
  LitAuthClient,
  WebAuthnProvider,
} from "@lit-protocol/lit-auth-client";
import {
  LitNodeClient,
  checkAndSignAuthMessage,
  decryptToString,
  encryptString,
} from "@lit-protocol/lit-node-client";
import { AuthMethodType, ProviderType } from "@lit-protocol/constants";
import { EncryptResponse, IRelayPollStatusResponse } from "@lit-protocol/types";
import { PKPEthersWallet, ethRequestHandler } from '@lit-protocol/pkp-ethers';
import { LitContracts } from '@lit-protocol/contracts-sdk';
import { SiweMessage } from 'siwe';

// const chain = "ethereum";
// const chainId = 1;
const chain = "polygon";
const chainId = 137;
// const dAppOwnerPrivateKey = "A_WALLET_PRIVATE_KEY"; // TODO replace this with a wallet the dApp owns


const Home = () => {
  const [username, setUsername] = useState("hello");
  const [messageToEncrypt, setMessageToEncrypt] = useState("woof woof");
  const [pkpEthAddress, setPkpEthAddress] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [dataToEncryptHash, setDataToEncryptHash] = useState("");

  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [encryptionResponse, setEncryptionResponse] =
    useState<EncryptResponse>();
  const [litAuthClient, setlitAuthClient] = useState<LitAuthClient>();
  const [litNodeClient, setLitNodeClient] = useState<LitNodeClient>();
  const [pkpPublicKey, setPkpPublicKey] = useState<string>();
  const [pkpResponse, setPkpResponse] = useState<IRelayPollStatusResponse>();

  const [dAppOwnerWallet, setDAppOwnerWallet] = useState<ethers.Wallet>();
  const [capacityTokenId, setCapacityTokenId] = useState();

  useEffect(() => {


    const client = new LitNodeClient({
      litNetwork: "manzano",
    });
    setLitNodeClient(client);
    const litAuthClient = new LitAuthClient({
      litRelayConfig: {
        // Request a Lit Relay Server API key here: https://forms.gle/RNZYtGYTY9BcD9MEA
        relayApiKey: "c8999b7e-8bb7-416d-a854-dac8632f9ee6_crossmint",
      },
      litNodeClient: client,
    });

    // Initialize WebAuthn provider
    litAuthClient.initProvider<WebAuthnProvider>(ProviderType.WebAuthn);
    setlitAuthClient(litAuthClient);
  }, []);

  useEffect(() => {
    const dAppOwnerWallet = new ethers.Wallet(
      dAppOwnerPrivateKey,
      new ethers.providers.JsonRpcProvider("https://chain-rpc.litprotocol.com/http"),
    );
    setDAppOwnerWallet(dAppOwnerWallet);

    const getCapacityTokenId = async () => {
      const litContracts = new LitContracts({
        network: "manzano",
        signer: dAppOwnerWallet,
      });
      await litContracts.connect();
      const { capacityTokenId } = await litContracts.mintCapacityCreditsNFT({
        // requestsPerDay: 1000,
        requestsPerSecond: 10,
        daysUntilUTCMidnightExpiration: 10,
      });
      console.log(`capacityTokenId: ${capacityTokenId.toString()}`);
      setCapacityTokenId(capacityTokenId.toString());
    }
    getCapacityTokenId().catch(console.error);
  }, []);

  const handleSignUp = async (event: React.FormEvent) => {
    event.preventDefault();

    const pkpPublicKey = await registerWithWebAuthn();
    console.log(pkpPublicKey);
    // setPkpPublicKey(pkpPublicKey);
  };

  async function registerWithWebAuthn() {
    const provider = litAuthClient!.getProvider(
      ProviderType.WebAuthn
    ) as WebAuthnProvider;
    // Register new WebAuthn credential
    const options = await provider!.register(username);

    // Verify registration and mint PKP through relay server
    const txHash = await provider!.verifyAndMintPKPThroughRelayer(options);
    // console.log("txHash");
    // console.log(txHash);
    const response = await provider.relay.pollRequestUntilTerminalState(txHash);
    // Return public key of newly minted PKP
    console.log(response);
    setPkpResponse(response);
    setPkpPublicKey(response.pkpPublicKey);
    setPkpEthAddress(response.pkpEthAddress!);
    return response.pkpPublicKey;
  }

  const handleSignIn = async (event: React.FormEvent) => {
    event.preventDefault();
    const provider = litAuthClient!.getProvider(
      ProviderType.WebAuthn
    ) as WebAuthnProvider;
    const authMethod = await provider.authenticate();
    console.log(authMethod);
    console.log(JSON.parse(authMethod.accessToken));

    return authMethod;
  };

  const handleEncryption = async (event: React.FormEvent) => {
    event.preventDefault();

    const encryption = await encrypt(messageToEncrypt);
  };

  async function encrypt(message: string) {
    await litNodeClient!.connect();

    // TODO: Remove duplicate
    const provider = litAuthClient!.getProvider(
      ProviderType.WebAuthn
    ) as WebAuthnProvider;
    const authMethod = await provider.authenticate();


    const capacityDelegationAuthSig = await createRemoteAuthSig();
    const sessionSigs = await provider.getSessionSigs({
      authMethod: authMethod,
      pkpPublicKey: pkpPublicKey!,
      sessionSigsParams: {
        chain: chain,
        resourceAbilityRequests: [
          {
            resource: new LitActionResource('*'),
            ability: LitAbility.AccessControlConditionDecryption
          }
        ],
        capacityDelegationAuthSig,
      },
    });

    // const pkpWallet = new PKPEthersWallet({
    //   controllerSessionSigs: sessionSigs,
    //   pkpPubKey: pkpPublicKey!,
    //   rpc: "https://chain-rpc.litprotocol.com/http",
    //   debug: true,
    //   litNetwork: "manzano",
    // });
    // await pkpWallet.init();

    // const statement =
    //   'This is a test statement. You can put anything you want here.';
    // const siweMessage = new SiweMessage({
    //   domain: 'localhost',
    //   address: pkpWallet.address,
    //   statement,
    //   uri: origin,
    //   version: '1',
    //   chainId: chainId,
    //   nonce: litNodeClient!.getLatestBlockhash()!,
    //   expirationTime: new Date(Date.now() + 60_000 * 60).toISOString(),
    // });
    // const messageToSign = siweMessage.prepareMessage();
    // const signature = await pkpWallet.signMessage(messageToSign);

    // const authSig = {
    //   sig: signature,
    //   derivedVia: 'web3.eth.personal.sign',
    //   signedMessage: messageToSign,
    //   address: pkpWallet.address,
    // };

    console.log("pkp eth address", pkpEthAddress);
    const accessControlConditions = [
      {
        contractAddress: "",
        standardContractType: "",
        chain,
        method: "",
        parameters: [":userAddress"],
        returnValueTest: {
          comparator: "=",
          value: pkpEthAddress,
        },
      },
    ];
    console.log(`accessControlConditions: ${JSON.stringify(accessControlConditions)}`);
    const { ciphertext, dataToEncryptHash } = await encryptString(
      {
        accessControlConditions,
        sessionSigs,
        // authSig,
        chain: chain,
        dataToEncrypt: message,
      },
      litNodeClient!
    );
    setEncryptionResponse({ ciphertext, dataToEncryptHash });
    console.log("encryption response");
    console.log({
      ciphertext,
      dataToEncryptHash,
    });
    setCiphertext(ciphertext);
    setDataToEncryptHash(dataToEncryptHash);

    return {
      ciphertext,
      dataToEncryptHash,
    };
  }

  const handleDecryption = async (event: React.FormEvent) => {
    event.preventDefault();

    const encryption = await decrypt();
    console.log(encryption);
  };

  async function decrypt() {
    await litNodeClient!.connect();

    // TODO: Remove duplicate
    const provider = litAuthClient!.getProvider(
      ProviderType.WebAuthn
    ) as WebAuthnProvider;
    const authMethod = await provider.authenticate();

    const { capacityDelegationAuthSig } = await litNodeClient?.createCapacityDelegationAuthSig({
      dAppOwnerWallet: dAppOwnerWallet!,
      capacityTokenId: capacityTokenId!,
      delegateeAddresses: [pkpEthAddress],
    })!;
    // const capacityDelegationAuthSig = await createRemoteAuthSig();
    const sessionSigs = await provider.getSessionSigs({
      authMethod: authMethod,
      pkpPublicKey: pkpPublicKey!,
      sessionSigsParams: {
        chain: chain,
        resourceAbilityRequests: [
          {
            resource: new LitActionResource('*'),
            ability: LitAbility.AccessControlConditionDecryption
          }
        ],
        capacityDelegationAuthSig,
      },
    });

    // const pkpWallet = new PKPEthersWallet({
    //   controllerSessionSigs: sessionSigs,
    //   pkpPubKey: pkpPublicKey!,
    //   rpc: "https://chain-rpc.litprotocol.com/http",
    //   debug: true,
    // });
    // await pkpWallet.init();

    // const statement =
    //   'This is a test statement. You can put anything you want here.';
    // const siweMessage = new SiweMessage({
    //   domain: 'localhost',
    //   address: pkpWallet.address,
    //   statement,
    //   uri: origin,
    //   version: '1',
    //   chainId: chainId,
    //   nonce: litNodeClient!.getLatestBlockhash()!,
    //   expirationTime: new Date(Date.now() + 60_000 * 60).toISOString(),
    // });
    // const messageToSign = siweMessage.prepareMessage();
    // const signature = await pkpWallet.signMessage(messageToSign);

    // const authSig = {
    //   sig: signature,
    //   derivedVia: 'web3.eth.personal.sign',
    //   signedMessage: messageToSign,
    //   address: pkpWallet.address,
    // };

    console.log("pkp eth address", pkpEthAddress);
    const accessControlConditions = [
      {
        contractAddress: "",
        standardContractType: "",
        chain,
        method: "",
        parameters: [":userAddress"],
        returnValueTest: {
          comparator: "=",
          value: pkpEthAddress,
        },
      },
    ];
    console.log(`accessControlConditions: ${JSON.stringify(accessControlConditions)}`);
    console.log("THis is running")
    console.log(sessionSigs)
    const decryptedString = await decryptToString(
      {
        accessControlConditions,
        ciphertext: ciphertext,
        dataToEncryptHash: dataToEncryptHash,
        sessionSigs,
        // authSig,
        chain: chain,
      },
      litNodeClient!
    );
    console.log("Decrypted Message", decryptedString);
    setDecryptedMessage(decryptedString);
    return { decryptedString };
  }
  // async function createRemoteAuthSig() {
  //     return {
  //       "sig": "0x71fad67d1970d13481faedc1352cab6ac3b336a70de6e09877c08a6eecd2338268a549140a4185f66d8b4574a373836c8b4b71463cc29afae387e693bf7beb2d1b",
  //       "derivedVia": "web3.eth.personal.sign",
  //       "signedMessage": "localhost wants you to sign in with your Ethereum account:\n0x3d355DEa427b4734F8815b0eB0EFDDA5b6fd3e03\n\nThis is the Crossmint lit node\n\nURI: http://localhost\nVersion: 1\nChain ID: 137\nNonce: 0xe28c98d9cabc8c12fc15829aec1d2d422aaec122b734b7ad01ffaa36929afa9d\nIssued At: 2024-01-31T21:57:32.532Z",
  //       "address": "0x3d355DEa427b4734F8815b0eB0EFDDA5b6fd3e03"
  //   }
  // }
  //   async function createRemoteAuthSig2() {
  //     return   {
  //       "sig": "0x7c75c9ebfa7077efed9b7c707775dfc6642c364931d2c3ed1415f93369bfdf7b2e329075a13762515418a2f8e212b9ea266f0a8af159ea40e2127da52fa698241b",
  //       "derivedVia": "web3.eth.personal.sign",
  //       "signedMessage": "localhost wants you to sign in with your Ethereum account:\n0x3d355DEa427b4734F8815b0eB0EFDDA5b6fd3e03\n\nThis is the Crossmint lit node\n\nURI: http://localhost\nVersion: 1\nChain ID: 137\nNonce: 0x13bb24780bc6daee28458e6f3520ceabeea25e8c27c964720b5e0e26b0730c9f\nIssued At: 2024-02-01T14:12:58.159Z",
  //       "address": "0x3d355DEa427b4734F8815b0eB0EFDDA5b6fd3e03"
  //   }
  // }


  // async function createRemoteAuthSig() {
  //   return     {
  //     "sig": "0xdcf81d84b1c6880134dd3601c8c51f77954a527bfecfd6cd07858f1c4c90a2e0400cd10d744330b4574f043989b84f0fb9c599d611e99d7c60ca0edb655260351b",
  //     "derivedVia": "web3.eth.personal.sign",
  //     "signedMessage": "localhost wants you to sign in with your Ethereum account:\n0x203F7dD921837f6Cdfc906cc17406e5bA0a87453\n\nThis is the Crossmint lit node\n\nURI: http://localhost\nVersion: 1\nChain ID: 137\nNonce: 0x7a5196212c6c9ef1877df150ef26856778067a2a51754a0976fab9a2c9eb8600\nIssued At: 2024-02-17T11:34:27.752Z",
  //     "address": "0x203F7dD921837f6Cdfc906cc17406e5bA0a87453"
  //   }
  // }
  async function createRemoteAuthSig() {
    await litNodeClient!.connect();

    let nonce = litNodeClient!.getLatestBlockhash();

    // Initialize the signer
    const wallet = new ethers.Wallet(dAppOwnerPrivateKey);
    const address = ethers.utils.getAddress(await wallet.getAddress());

    // Craft the SIWE message
    const domain = 'localhost';
    // const origin = 'https://localhost/login';
    const statement =
      '2 This is the Crossmint lit node';
    const siweMessage = new SiweMessage({
      domain,
      address: address,
      statement,
      uri: origin,
      version: '1',
      chainId: chainId,
      nonce: nonce!,
    });
    const messageToSign = siweMessage.prepareMessage();

    // Sign the message and format the authSig
    const signature = await wallet.signMessage(messageToSign);

    const authSig = {
      sig: signature,
      derivedVia: 'web3.eth.personal.sign',
      signedMessage: messageToSign,
      address: address,
    };

    console.log("AUTH SIG")
    console.log(authSig);
    return authSig;
  }

  return (
<div>
      <h1>Passkey demo</h1>
      {/* <p>{status}</p> */}
      <form onSubmit={handleSignUp}>
        <label htmlFor="username">Username</label>
        <input
          id="username"
          name="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <button type="submit">Sign up with passkeys</button>
      </form>
      {/* <form onSubmit={handleSignIn}>
        <button type="submit">Sign in with passkeys</button>
      </form> */}
      <label htmlFor="pkpEthAddress">Subtmit PKP Eth Address</label>
      <input
        id="pkpEthAddress"
        name="pkpEthAddress"
        value={pkpEthAddress}
        onChange={(e) => setPkpEthAddress(e.target.value)}
      />
      <label htmlFor="pkpPublicKey">Subtmit PKP public key</label>
      <input
        id="pkpPublicKey"
        name="pkpPublicKey"
        value={pkpPublicKey}
        onChange={(e) => setPkpPublicKey(e.target.value)}
      />
      <form onSubmit={handleEncryption}>
        <label htmlFor="encryptionMessage">Encryption Message</label>
        <input
          id="encryptionMessage"
          name="encryptionMessage"
          value={messageToEncrypt}
          onChange={(e) => setMessageToEncrypt(e.target.value)}
        />
        <button type="submit">Encrypt message</button>
      </form>
      <p>Decrypted Message: {decryptedMessage}</p>
      <form onSubmit={handleDecryption}>
        <label htmlFor="ciphertext">Cypher Text</label>
        <input
          id="ciphertext"
          name="ciphertext"
          value={ciphertext}
          onChange={(e) => setCiphertext(e.target.value)}
        />
        <label htmlFor="dataToEncryptHash">Data to encrypt hash</label>
        <input
          id="dataToEncryptHash"
          name="dataToEncryptHash"
          value={dataToEncryptHash}
          onChange={(e) => setDataToEncryptHash(e.target.value)}
        />
        <button type="submit">Decrypt message</button>
      </form>
    </div>
  );
};

export default Home;