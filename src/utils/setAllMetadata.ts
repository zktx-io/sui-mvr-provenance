import { Transaction, TransactionResult } from '@mysten/sui/transactions';

import { MvrConfig } from './type';

const splitBase64IntoChunks = (base64: string, chunkCount: number) => {
  const chunkSize = Math.ceil(base64.length / chunkCount);
  const chunks = [];
  for (let i = 0; i < chunkCount; i++) {
    chunks.push(base64.slice(i * chunkSize, (i + 1) * chunkSize));
  }
  return chunks;
};

const setMetaData = (
  target: string,
  key: string,
  value: string,
  registryObj: {
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
): ((tx: Transaction) => TransactionResult) => {
  return (transaction: Transaction) => {
    return transaction.moveCall({
      target,
      arguments: [
        registryObj,
        appCap,
        transaction.pure.string(key),
        transaction.pure.string(value),
      ],
    });
  };
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
): ((tx: Transaction) => TransactionResult) => {
  const chunk = splitBase64IntoChunks(provenance, 4);
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
    ['provenance_0', chunk[0]],
    ['provenance_1', chunk[1]],
    ['provenance_2', chunk[2]],
    ['provenance_3', chunk[3]],
  ];

  return (transaction: Transaction) => {
    let lastResult: TransactionResult | undefined;

    for (const [key, value] of keys) {
      lastResult = transaction.add(setMetaData(metadataTarget, key, value, registry, appCap));
    }

    return lastResult!;
  };
};
