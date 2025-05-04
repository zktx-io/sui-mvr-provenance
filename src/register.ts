import * as core from '@actions/core';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SuinsClient } from '@mysten/suins';

import { getSigner } from './utils/getSigner';
import { loadMvrConfig } from './utils/load';

const main = async () => {
  const config = await loadMvrConfig();
  const { signer, isGitSigner } = await getSigner(config);

  const package_name = config.package_name!;

  const client = new SuiClient({ url: getFullnodeUrl(config.network) });
  const suinsClient = new SuinsClient({
    client,
    network: config.network,
  });

  const record = await suinsClient.getNameRecord(
    package_name.endsWith('.sui') ? package_name : `${package_name}.sui`,
  );

  if (!record) {
    core.setFailed(`❌ Name record not found for ${package_name}`);
    return;
  }

  const obj = await client.getObject({
    id: record.nftId,
    options: { showOwner: true, showType: true },
  });

  if (!obj) {
    core.setFailed(`❌ Object not found for ${package_name}`);
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

  if (obj.data!.type?.endsWith('::SuinsRegistration')) {
    core.setFailed(`❌ Object ${record.nftId} is not a Suins object`);
    return;
  }
};

main().catch(err => {
  core.setFailed(`❌ Error running deploy script: ${err}`);
  process.exit(1);
});
