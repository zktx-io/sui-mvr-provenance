import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';

const main = async () => {
  console.log('contract deploy');
  const suiClient = new SuiClient({ url: getFullnodeUrl('testnet') });
};

main();
