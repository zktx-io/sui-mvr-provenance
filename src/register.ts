import * as core from '@actions/core';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { SuinsClient } from '@mysten/suins';

import { getSigner } from './utils/getSigner';
import { loadMvrConfig } from './utils/load';
import { mvrResolver } from './utils/mvrResolver';

const main = async () => {
  const config = await loadMvrConfig();
  const { signer, isGitSigner } = await getSigner(config);

  if (config.package_name && config.package_name.split('/').length !== 2) {
    return;
  }

  const suins = config.package_name?.split('/')[0].replace('@', '')!;
  const pkgName = config.package_name?.split('/')[1]!;

  const client = new SuiClient({ url: getFullnodeUrl('mainnet') });
  const suinsClient = new SuinsClient({
    client,
    network: 'mainnet',
  });

  const record = await suinsClient.getNameRecord(suins.endsWith('.sui') ? suins : `${suins}.sui`);

  if (!record) {
    core.setFailed(`❌ Name record not found for ${suins}`);
    return;
  }

  const obj = await client.getObject({
    id: record.nftId,
    options: { showOwner: true, showType: true },
  });

  if (!obj) {
    core.setFailed(`❌ Object not found for ${suins}`);
    return;
  }

  if (
    (typeof obj.data!.owner! === 'object' &&
      'AddressOwner' in obj.data!.owner! &&
      obj.data!.owner!.AddressOwner) !== config.owner
  ) {
    core.setFailed(
      `❌ Object ${record.nftId} is not owned by ${config.owner}. Current owner: ${(obj.data!.owner! as any).AddressOwner}`,
    );
    return;
  }

  if (!obj.data!.type?.endsWith('::SuinsRegistration')) {
    core.setFailed(`❌ Object ${record.nftId} is not a Suins object`);
    return;
  }

  const registryObj = await suinsClient.getNameRecord('registry-obj@mvr');
  const cache = await mvrResolver(['@mvr/core', config.package_name], config.network);

  if (!registryObj || !registryObj.targetAddress) {
    core.setFailed(`❌ Registry object not found`);
    return;
  }

  if (cache[config.package_name]) {
    // TODO Update
  } else {
    const transaction = new Transaction();
    transaction.setSender(config.owner);

    const appCap = transaction.moveCall({
      target: `${cache['@mvr/core']}::move_registry::register`,
      arguments: [
        transaction.object(registryObj.targetAddress),
        transaction.object(record.nftId),
        transaction.pure.string(pkgName),
        transaction.object.clock(),
      ],
    });

    transaction.moveCall({
      target: `${cache['@mvr/core']}::move_registry::set_metadata`,
      arguments: [
        transaction.object(registryObj.targetAddress),
        appCap,
        transaction.pure.string('description'),
        transaction.pure.string(config.package_desc),
      ],
    });
  }
};

main().catch(err => {
  core.setFailed(`❌ Error running deploy script: ${err}`);
  process.exit(1);
});
