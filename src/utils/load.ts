import fs from 'fs/promises';
import path from 'path';

import * as core from '@actions/core';
import { SuiClient } from '@mysten/sui/client';
import { toBase64 } from '@mysten/sui/utils';

import { BytecodeDump, Deploy, MvrConfig } from './type';

export const loadMvrConfig = async (): Promise<MvrConfig> => {
  const configPath = path.resolve('../mvr.config.json');
  const configRaw = await fs.readFile(configPath, 'utf-8');
  return JSON.parse(configRaw) as MvrConfig;
};

export const loadBytecodeDump = async (): Promise<BytecodeDump> => {
  const dumpPath = path.resolve('../bytecode.dump.json');
  const dumpRaw = await fs.readFile(dumpPath, 'utf-8');
  return JSON.parse(dumpRaw) as BytecodeDump;
};

export const loadDeploy = async (): Promise<Deploy> => {
  const dumpPath = path.resolve('../deploy.json');
  const dumpRaw = await fs.readFile(dumpPath, 'utf-8');
  return JSON.parse(dumpRaw) as Deploy;
};

export const loadProvenance = async (): Promise<string> => {
  const dumpPath = path.resolve('../mvr.intoto.jsonl');
  const dumpRaw = await fs.readFile(dumpPath, 'utf-8');
  return toBase64(new TextEncoder().encode(dumpRaw));
};

export const loadUpgradeCap = async (
  id: string,
  client: SuiClient,
): Promise<{ package: string; version: string }> => {
  const { data } = await client.getObject({
    id,
    options: { showContent: true, showType: true },
  });

  if (
    !data ||
    data.type !== '0x2::package::UpgradeCap' ||
    data.content?.dataType !== 'moveObject'
  ) {
    core.setFailed(`❌ Upgrade cap not found: ${id}`);
    process.exit(1);
  }

  const fields = data.content.fields as { package: string; version: string };

  if (!fields.package) {
    core.setFailed(`❌ 'package' field not found in UpgradeCap`);
    process.exit(1);
  }

  return {
    package: fields.package,
    version: fields.version,
  };
};
