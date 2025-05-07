// @mysten/mvr-static
import { Network } from './type';

const MAX_BATCH_SIZE = 25; // files to process per batch.
const MAINNET_API_URL = 'https://mainnet.mvr.mystenlabs.com';
const TESTNET_API_URL = 'https://testnet.mvr.mystenlabs.com';

const batch = <T>(array: T[], batchSize: number = MAX_BATCH_SIZE) => {
  const result = [];
  for (let i = 0; i < array.length; i += batchSize) {
    result.push(array.slice(i, i + batchSize)); // Create batches
  }
  return result;
};

export const mvrResolver = async (packages: string[], network: Network) => {
  const batches = batch(packages, 50);

  const results: Record<string, string> = {};

  const apiUrl = network === 'testnet' ? TESTNET_API_URL : MAINNET_API_URL;

  await Promise.all(
    batches.map(async batch => {
      const response = await fetch(`${apiUrl}/v1/resolution/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          names: batch,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(`Failed to resolve packages: ${errorBody?.message}`);
      }

      const data = await response.json();

      if (!data?.resolution) return;

      for (const pkg of Object.keys(data?.resolution)) {
        const pkgData = data.resolution[pkg]?.package_id;

        if (!pkgData) continue;

        results[pkg] = pkgData;
      }
    }),
  );

  return results;
};
