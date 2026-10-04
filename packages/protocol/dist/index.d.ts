export declare const PROTOCOL_VERSION = "0.1";
export type ProductType = 'application' | 'agent' | 'tool' | 'game' | 'model' | 'service' | 'package' | 'plugin';
export type InterfaceType = 'web' | 'api' | 'agent' | 'cli' | 'desktop' | 'mobile' | 'download' | 'stream';
export interface Artifact {
    target: string;
    uri: string;
    digest: string;
    size?: number;
    mediaType?: string;
}
export interface ProductManifest {
    protocol: 'distribution/0.1';
    product: {
        id: string;
        name: string;
        type: ProductType;
        publisher: string;
        description?: string;
    };
    version: string;
    publishedAt: string;
    artifacts?: Artifact[];
    interfaces?: Array<{
        type: InterfaceType;
        uri: string;
        capabilities?: string[];
    }>;
    requirements?: Record<string, string>;
    permissions?: string[];
    pricing?: {
        model: 'free' | 'paid' | 'subscription' | 'usage';
        currency?: string;
        amount?: number;
        unit?: string;
    };
    metadata?: Record<string, unknown>;
}
export interface SignedManifest {
    manifest: ProductManifest;
    signature: string;
    algorithm: 'ed25519';
    publicKey: string;
}
export declare function canonicalize(value: unknown): string;
export declare function digest(value: unknown): string;
export declare function signManifest(manifest: ProductManifest, privateKey: string): SignedManifest;
export declare function verifyManifest(signed: SignedManifest): boolean;
export declare function generatePublisherKeypair(): {
    publicKey: string;
    privateKey: string;
};
