import * as core from '@actions/core';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { SuinsClient } from '@mysten/suins';

import { addAllMetadata } from './utils/addAllMetadata';
import { getSigner } from './utils/getSigner';
import { GitSigner } from './utils/gitSigner';
import { loadDeploy, loadMvrConfig, loadProvenance, loadUpgradeCap } from './utils/load';
import { mvrResolver } from './utils/mvrResolver';

const main = async () => {
  const config = await loadMvrConfig();
  const provenance = await loadProvenance();
  const deploy = await loadDeploy();

  const { signer, isGitSigner } = await getSigner(config);

  if (config.app_name && config.app_name.split('/').length !== 2) {
    process.exit(1);
  }

  if (config.network !== 'mainnet') {
    core.setFailed(`❌ Network ${config.network} is not supported. Only mainnet is supported.`);
    process.exit(1);
  }

  const suins = config.app_name?.split('/')[0].replace('@', '')!;
  const pkgName = config.app_name?.split('/')[1]!;

  const client = new SuiClient({ url: getFullnodeUrl('mainnet') });
  const suinsClient = new SuinsClient({
    client,
    network: 'mainnet',
  });

  const { version } = await loadUpgradeCap(deploy.upgrade_cap, client);
  const record = await suinsClient.getNameRecord(suins.endsWith('.sui') ? suins : `${suins}.sui`);

  if (!record) {
    core.setFailed(`❌ Name record not found for ${suins}`);
    process.exit(1);
  }

  const { data } = await client.getObject({
    id: record.nftId,
    options: { showOwner: true, showType: true },
  });

  if (!data) {
    core.setFailed(`❌ Object not found for ${suins}`);
    process.exit(1);
  }

  if (
    (typeof data!.owner! === 'object' &&
      'AddressOwner' in data!.owner! &&
      data!.owner!.AddressOwner) !== config.owner
  ) {
    core.setFailed(
      `❌ Object ${record.nftId} is not owned by ${config.owner}. Current owner: ${(data!.owner! as any).AddressOwner}`,
    );
    process.exit(1);
  }

  if (!data!.type?.endsWith('::SuinsRegistration')) {
    core.setFailed(`❌ Object ${record.nftId} is not a Suins object`);
    process.exit(1);
  }

  const registryObj = await suinsClient.getNameRecord('registry-obj@mvr');
  const cache = await mvrResolver(['@mvr/core', '@mvr/metadata', config.app_name], config.network);

  if (!registryObj || !registryObj.targetAddress) {
    core.setFailed(`❌ Registry object not found`);
    process.exit(1);
  }

  if (!cache['@mvr/core'] || !cache['@mvr/metadata']) {
    core.setFailed(`❌ Package not found`);
    process.exit(1);
  }

  if (!cache[config.app_name]) {
    const transaction = new Transaction();
    transaction.setSender(config.owner);

    const registry = transaction.object(registryObj.targetAddress);
    const nftId = transaction.object(record.nftId);

    const appCap = transaction.moveCall({
      target: `${cache['@mvr/core']}::move_registry::register`,
      arguments: [registry, nftId, transaction.pure.string(pkgName), transaction.object.clock()],
    });

    transaction.add(
      addAllMetadata(
        `${cache['@mvr/core']}::move_registry::set_metadata`,
        registry,
        appCap,
        config,
        deploy,
        provenance,
      ),
    );

    const packageInfo = transaction.moveCall({
      target: `${cache['@mvr/metadata']}::package_info::new`,
      arguments: [transaction.object(deploy.upgrade_cap)],
    });

    const git = transaction.moveCall({
      target: `${cache['@mvr/metadata']}::git::new`,
      arguments: [
        transaction.pure.string(process.env.GIT_REPO ?? ''),
        transaction.pure.string(process.env.GIT_SUBDIR ?? ''),
        transaction.pure.string(process.env.GIT_COMMIT ?? ''),
      ],
    });

    transaction.moveCall({
      target: `${cache['@mvr/metadata']}::package_info::set_git_versioning`,
      arguments: [packageInfo, transaction.pure.u64(version), git],
    });

    transaction.moveCall({
      target: `${cache['@mvr/core']}::move_registry::assign_package`,
      arguments: [registry, appCap, packageInfo],
    });

    const recipient = transaction.moveCall({
      target: '0x2::tx_context::sender',
    });

    transaction.moveCall({
      target: `${cache['@mvr/metadata']}::package_info::transfer`,
      arguments: [packageInfo, recipient],
    });

    transaction.transferObjects([appCap], recipient);

    const { input } = await client.dryRunTransactionBlock({
      transactionBlock: await transaction.build({ client }),
    });
    transaction.setGasBudget(parseInt(input.gasData.budget));

    const { digest: txDigest } = await client.signAndExecuteTransaction({
      signer,
      transaction,
    });

    const { effects: txEffect, objectChanges } = await client.waitForTransaction({
      digest: txDigest,
      options: { showEffects: true, showObjectChanges: true },
    });

    if (!txEffect || txEffect.status.status !== 'success') {
      core.setFailed(
        `❌ Transaction failed: ${txDigest} - ${txEffect?.status.error ?? 'Unknown error'}`,
      );
      process.exit(1);
    } else {
      const [appCap] = (objectChanges || []).filter(
        item => item.type === 'created' && item.objectType.endsWith('::app_record::AppCap'),
      );
      const [pkgInfo] = (objectChanges || []).filter(
        item => item.type === 'created' && item.objectType.endsWith('::package_info::PackageInfo'),
      );
      if (isGitSigner) {
        const message = new TextEncoder().encode(
          JSON.stringify({ url: `https://suiscan.xyz/${config.network}/tx/${txDigest}` }),
        );
        await (signer as GitSigner).signPersonalMessage(message, true);
      }
      core.info(
        `✅ Transaction executed successfully: https://suiscan.xyz/${config.network}/tx/${txDigest}`,
      );
      core.info(`⚠️ To update metadata later, please add the following to your mvr.config.json:`);
      core.info(`  "app_cap": "${(appCap as any).objectId}",`);
      core.info(`  "pkg_info": "${(pkgInfo as any).objectId}"`);
    }
  } else if (!!config.app_cap && !!config.pkg_info) {
    const transaction = new Transaction();
    transaction.setSender(config.owner);

    const registry = transaction.object(registryObj.targetAddress);
    const appCap = transaction.object(config.app_cap);
    const packageInfo = transaction.object(config.pkg_info);

    transaction.add(
      addAllMetadata(
        `${cache['@mvr/core']}::move_registry::set_metadata`,
        registry,
        appCap,
        config,
        deploy,
        provenance,
      ),
    );

    transaction.moveCall({
      target: `${cache['@mvr/metadata']}::package_info::unset_git_versioning`,
      arguments: [packageInfo, transaction.pure.u64(parseInt(version) - 1)],
    });

    const git = transaction.moveCall({
      target: `${cache['@mvr/metadata']}::git::new`,
      arguments: [
        transaction.pure.string(process.env.GIT_REPO ?? ''),
        transaction.pure.string(process.env.GIT_SUBDIR ?? ''),
        transaction.pure.string(process.env.GIT_COMMIT ?? ''),
      ],
    });

    transaction.moveCall({
      target: `${cache['@mvr/metadata']}::package_info::set_git_versioning`,
      arguments: [packageInfo, transaction.pure.u64(version), git],
    });

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
  } else {
    core.info(`ℹ️ Detected existing MVR registration for ${config.app_name}`);
    core.info(`ℹ️ Use app_cap + pkg_info to update metadata only`);
    process.exit(1);
  }
};

main().catch(err => {
  core.setFailed(`❌ Error running deploy script: ${err}`);
  process.exit(1);
});
