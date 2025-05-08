import { Transaction, TransactionResult } from '@mysten/sui/transactions';

const unsetMetaData = (
  target: string,
  key: string,
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
      arguments: [registryObj, appCap, transaction.pure.string(key)],
    });
  };
};

export const unsetAllMetadata = (
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
): ((tx: Transaction) => TransactionResult) => {
  const keys: string[] = [
    'description',
    'homepage_url',
    'documentation_url',
    'icon_url',
    'contact',
    'deploy',
    'provenance',
  ];

  return (transaction: Transaction) => {
    let lastResult: TransactionResult | undefined;

    for (const key of keys) {
      lastResult = transaction.add(unsetMetaData(metadataTarget, key, registry, appCap));
    }

    return lastResult!;
  };
};
