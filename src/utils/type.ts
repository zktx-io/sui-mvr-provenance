export type Network = 'mainnet' | 'testnet';

export interface MvrConfig {
  network: Network;
  owner: string;
  app_name: string;
  app_desc: string;
  upgrade_cap?: string;
  app_cap?: string;
  pkg_info?: string;
  icon_url?: string;
  homepage_url?: string;
  documentation_url?: string;
  contact?: string;
}

export interface BytecodeDump {
  modules: string[]; // base64-encoded Move modules
  dependencies: string[]; // object references (addresses)
  digest: number[]; // module digest, usually a 32-byte array
}

export interface Deploy {
  digest: string;
  modules: string[];
  dependencies: string[];
  upgrade_cap: string;
}
