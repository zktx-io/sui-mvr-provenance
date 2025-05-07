export type Network = 'mainnet' | 'testnet';

export interface MvrConfig {
  network: Network;
  owner: string;
  package_name: string;
  package_desc: string;
  upgrade_cap?: string;
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
