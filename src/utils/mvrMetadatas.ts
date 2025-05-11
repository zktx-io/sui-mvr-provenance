import * as core from '@actions/core';
import { Transaction, TransactionResult } from '@mysten/sui/transactions';

import { MvrConfig, Network } from '../types';

const splitBase64IntoChunks = (base64: string, chunkCount: number) => {
  const chunkSize = Math.ceil(base64.length / chunkCount);
  const chunks = [];
  for (let i = 0; i < chunkCount; i++) {
    chunks.push(base64.slice(i * chunkSize, (i + 1) * chunkSize));
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
  const chunks = splitBase64IntoChunks(provenance, 4);
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
    ['provenance_0', chunks[0]],
    ['provenance_1', chunks[1]],
    ['provenance_2', chunks[2]],
    ['provenance_3', chunks[3]],
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
