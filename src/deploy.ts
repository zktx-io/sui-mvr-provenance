import fs from 'fs/promises';
import path from 'path';

import * as core from '@actions/core';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction, UpgradePolicy } from '@mysten/sui/transactions';

import { getSigner } from './utils/getSigner';
import { GitSigner } from './utils/gitSigner';
import { loadBytecodeDump, loadMvrConfig, loadUpgradeCap } from './utils/load';
import { Deploy } from './utils/type';

const main = async () => {
  const config = await loadMvrConfig();
  const dump = await loadBytecodeDump();
  const { signer, isGitSigner } = await getSigner(config);

  core.info('📦 MVR Config:');
  core.info(JSON.stringify(config, null, 2));

  core.info('📄 Bytecode Dump:');
  core.info(JSON.stringify(dump));

  const { modules, dependencies, digest } = dump;

  const client = new SuiClient({
    url: getFullnodeUrl(config.network),
  });

  const transaction = new Transaction();
  transaction.setSender(config.owner);

  if (config.upgrade_cap) {
    const { package: packageId } = await loadUpgradeCap(config.upgrade_cap, client);
    const cap = transaction.object(config.upgrade_cap);
    const ticket = transaction.moveCall({
      target: '0x2::package::authorize_upgrade',
      arguments: [
        cap,
        transaction.pure.u8(UpgradePolicy.COMPATIBLE),
        transaction.pure.vector('u8', digest),
      ],
    });
    const upgrade = transaction.upgrade({
      modules,
      dependencies,
      package: packageId,
      ticket,
    });
    transaction.moveCall({
      target: '0x2::package::commit_upgrade',
      arguments: [cap, upgrade],
    });
  } else {
    const publish = transaction.publish({
      modules,
      dependencies,
    });
    transaction.transferObjects([publish], config.owner);
  }

  const { input } = await client.dryRunTransactionBlock({
    transactionBlock: await transaction.build({ client }),
  });
  transaction.setGasBudget(parseInt(input.gasData.budget));

  const { digest: txDigest } = await client.signAndExecuteTransaction({
    signer,
    transaction,
  });

  const { effects: txEffect } = await client.waitForTransaction({
    digest: txDigest,
    options: { showEffects: true },
  });

  if (!txEffect || txEffect.status.status !== 'success') {
    core.setFailed(
      `❌ Transaction failed: ${txDigest} - ${txEffect?.status.error ?? 'Unknown error'}`,
    );
    process.exit(1);
  } else {
    let upgrade_cap = config.upgrade_cap;

    txEffect.created!.forEach(obj => {
      if (obj.owner === 'Immutable') {
        core.info(`✅ Package Obj: ${obj.reference.objectId}`);
      } else {
        upgrade_cap = obj.reference.objectId;
        core.info(`✅ Upgrade Cap: ${obj.reference.objectId}`);
      }
    });

    const deploy: Deploy = {
      digest: txDigest,
      modules,
      dependencies,
      upgrade_cap: upgrade_cap!,
    };
    await fs.writeFile(path.join(process.cwd(), '../deploy.json'), JSON.stringify(deploy));

    if (isGitSigner) {
      const message = new TextEncoder().encode(
        JSON.stringify({ url: `https://suiscan.xyz/${config.network}/tx/${txDigest}` }),
      );
      await (signer as GitSigner).signPersonalMessage(message, true);
    }

    core.info(
      `✅ Transaction executed successfully: https://suiscan.xyz/${config.network}/tx/${txDigest}`,
    );
  }
};

main().catch(err => {
  core.setFailed(`❌ Error running deploy script: ${err}`);
  process.exit(1);
});
