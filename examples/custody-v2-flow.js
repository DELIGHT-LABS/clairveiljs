import { createClairveilDappClient, createArtifactVerifier } from 'clairveiljs/dapp';

/** Page-side example: the extension owns all privacy keys and proving. The host
 * must first obtain network/site/operation approval through the custody provider.
 * chainWallet is the Keplr/Cosmos or MetaMask/EIP-1193 adapter for the selected actor. */
export function createV2Dapp({ custodyProvider, chainWallet, deployment, broadcastCosmos }) {
  if (deployment.protocol !== 'audit-field-v2') throw new Error('Explicit V2 deployment required');
  return createClairveilDappClient({ custodyProvider, chainWallet, broadcastCosmos,
    validateArtifact: createArtifactVerifier({ protocol: 'audit-field-v2',
      profileDigest: deployment.profileDigest, chainId: deployment.chainId,
      protocolChainId: deployment.protocolChainId, assetDenom: deployment.assetDenom,
      ...(deployment.contractAddress ? { contractAddress: deployment.contractAddress } : {})
    })
  });
}
