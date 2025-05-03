export type Network = 'mainnet' | 'testnet' | 'devnet';

export interface MvrConfig {
  network: Network;
  owner: string;
  package_name?: string;
  package_id?: string;
  upgrade_id?: string;
}

export interface BytecodeDump {
  modules: string[]; // base64-encoded Move modules
  dependencies: string[]; // object references (addresses)
  digest: number[]; // module digest, usually a 32-byte array
}
