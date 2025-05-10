import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';

export const getGasBudget = async (tx: Transaction, client: SuiClient): Promise<number> => {
  const txJson = await tx.toJSON();
  const clone = Transaction.from(txJson);
  const { input } = await client.dryRunTransactionBlock({
    transactionBlock: await clone.build({ client }),
  });
  return parseInt(input.gasData.budget);
};
