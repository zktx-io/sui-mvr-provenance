import { Transaction, TransactionResult } from '@mysten/sui/transactions';

import { Deploy, MvrConfig } from './type';

export const setMetaData = (
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

export const addAllMetadata = (
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
  deploy: Deploy,
  provenance: any,
): ((tx: Transaction) => TransactionResult) => {
  const keys: [string, string | undefined][] = [
    ['description', config.app_desc],
    ['homepage_url', config.homepage_url],
    ['documentation_url', config.documentation_url],
    ['icon_url', config.icon_url],
    ['contact', config.contact],
    // ['deploy', JSON.stringify(deploy)],
    // ['provenance', JSON.stringify(provenance)],
  ];

  return (transaction: Transaction) => {
    let lastResult: TransactionResult | undefined;

    for (const [key, value] of keys) {
      if (value) {
        lastResult = transaction.add(setMetaData(metadataTarget, key, value, registry, appCap));
      }
    }

    return lastResult!;
  };
};
