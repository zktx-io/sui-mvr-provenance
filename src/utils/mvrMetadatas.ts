import { Transaction, TransactionResult } from '@mysten/sui/transactions';

import { MvrConfig, Network } from '../types';

const splitBase64ByByteLength = (base64: string, maxBytes: number): string[] => {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(base64);
  const chunks: string[] = [];

  for (let i = 0; i < bytes.length; i += maxBytes) {
    const slice = bytes.slice(i, i + maxBytes);
    chunks.push(new TextDecoder().decode(slice));
  }

  return chunks;
};

export const setAllMetadata = (
  metadataTarget: string,
  registry: {
    $kind: 'Input';
    Input: number;
    type?: 'object';
  },
  appCap:
    | TransactionResult
    | {
        $kind: 'Input';
        Input: number;
        type?: 'object';
      },
  config: MvrConfig,
  tx_digest: string,
  provenance: string,
): ((tx: Transaction) => void) => {
  const chunks = splitBase64ByByteLength(provenance, 16380);
  const keys: [string, string][] = [
    ['description', config.app_desc],
    ['homepage_url', config.homepage_url ?? (process.env.GIT_REPO || '')],
    [
      'documentation_url',
      config.documentation_url ?? (process.env.GIT_REPO ? `${process.env.GIT_REPO}#readme` : ''),
    ],
    ['icon_url', config.icon_url || ''],
    ['contact', config.contact || ''],
    ['tx_digest', tx_digest],
    ...chunks.map((chunk, i): [string, string] => [`provenance_${i}`, chunk]),
  ];

  return (transaction: Transaction) => {
    for (const [key, value] of keys) {
      transaction.moveCall({
        target: metadataTarget,
        arguments: [registry, appCap, transaction.pure.string(key), transaction.pure.string(value)],
      });
    }
  };
};

export const unsetAllMetadata = async (
  network: Network,
  name: string,
  metadataTarget: string,
  registry: {
    $kind: 'Input';
    Input: number;
    type?: 'object';
  },
  appCap:
    | TransactionResult
    | {
        $kind: 'Input';
        Input: number;
        type?: 'object';
      },
): Promise<(tx: Transaction) => void> => {
  const response = await fetch(`https://${network}.mvr.mystenlabs.com/v1/names/${name}`, {
    method: 'GET',
  });
  const json = await response.json();
  const keys: string[] = Object.keys(json.metadata);

  return (transaction: Transaction) => {
    for (const key of keys) {
      transaction.moveCall({
        target: metadataTarget,
        arguments: [registry, appCap, transaction.pure.string(key)],
      });
    }
  };
};
