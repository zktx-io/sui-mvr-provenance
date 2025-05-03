import fs from 'fs/promises';
import path from 'path';

import { BytecodeDump, MvrConfig } from './type';

export const loadMvrConfig = async (baseDir: string = '.'): Promise<MvrConfig> => {
  const configPath = path.join(baseDir, 'mvr.config.json');
  const configRaw = await fs.readFile(configPath, 'utf-8');
  return JSON.parse(configRaw) as MvrConfig;
};

export const loadBytecodeDump = async (baseDir: string = '.'): Promise<BytecodeDump> => {
  const dumpPath = path.join(baseDir, 'bytecode.dump.json');
  const dumpRaw = await fs.readFile(dumpPath, 'utf-8');
  return JSON.parse(dumpRaw) as BytecodeDump;
};
