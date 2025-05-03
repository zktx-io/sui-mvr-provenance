import * as core from '@actions/core';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { loadBytecodeDump, loadMvrConfig } from './utils/load';
import { Transaction, UpgradePolicy } from '@mysten/sui/transactions';
import { getSigner } from './utils/getSigner';

const main = async () => {
  const config = await loadMvrConfig();
  const dump = await loadBytecodeDump();
  const { signer, isGitSigner } = await getSigner(config);

  core.info('📦 MVR Config:');
  core.info(JSON.stringify(config, null, 2));

  core.info('📄 Bytecode Dump:');
  core.info(JSON.stringify(dump, null, 2));

  const { modules, dependencies, digest } = dump;

  const client = new SuiClient({
    url: getFullnodeUrl(config.network),
  });

  const transaction = new Transaction();
  transaction.setSender(config.owner);

  if (config.upgrade_cap_id && config.package_id) {
    const cap = transaction.object(config.upgrade_cap_id);
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
      package: config.package_id,
      ticket,
    });
    transaction.moveCall({
      target: '0x2::package::commit_upgrade',
      arguments: [cap, upgrade],
    });
  } else {
    transaction.transferObjects(
      [
        transaction.publish({
          modules,
          dependencies,
        }),
      ],
      config.owner,
    );
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
    options: { showEffects: true, showEvents: true },
  });

  core.info(`✅ Transaction executed successfully.: ${txDigest}`);
};

main().catch(err => {
  core.setFailed(`❌ Error running test script: ${err}`);
  process.exit(1);
});
