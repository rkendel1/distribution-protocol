import { type SignedManifest, type ProductManifest } from '@distribution-protocol/protocol';
export interface ResolveRequest {
    productId: string;
    consumer?: {
        target?: string;
        interface?: string;
        capability?: string;
    };
    version?: string;
}
export interface ResolveResult {
    manifest: ProductManifest;
    selected?: {
        target?: string;
        type?: string;
        uri: string;
        digest?: string;
    };
}
export declare class InMemoryRegistry {
    private products;
    publish(signed: SignedManifest): void;
    get(productId: string, version?: string): SignedManifest;
    resolve(req: ResolveRequest): ResolveResult;
}
