import fs from 'fs/promises';
import path from 'path';

import { BytecodeDump, MvrConfig } from './type';

export const loadMvrConfig = async (): Promise<MvrConfig> => {
  const configPath = path.resolve('mvr.config.json');
  const configRaw = await fs.readFile(configPath, 'utf-8');
  return JSON.parse(configRaw) as MvrConfig;
};

export const loadBytecodeDump = async (): Promise<BytecodeDump> => {
  const dumpPath = path.resolve('bytecode.dump.json');
  const dumpRaw = await fs.readFile(dumpPath, 'utf-8');
  return JSON.parse(dumpRaw) as BytecodeDump;
};
