import { verifyManifest } from '@distribution-protocol/protocol';
export class InMemoryRegistry {
    products = new Map();
    publish(signed) {
        if (!verifyManifest(signed))
            throw new Error('INVALID_SIGNATURE');
        const id = signed.manifest.product.id;
        const versions = this.products.get(id) ?? new Map();
        if (versions.has(signed.manifest.version))
            throw new Error('VERSION_EXISTS');
        versions.set(signed.manifest.version, signed);
        this.products.set(id, versions);
    }
    get(productId, version) {
        const versions = this.products.get(productId);
        if (!versions)
            throw new Error('NOT_FOUND');
        if (version) {
            const found = versions.get(version);
            if (!found)
                throw new Error('NOT_FOUND');
            return found;
        }
        const latest = [...versions.values()].sort((a, b) => a.manifest.version.localeCompare(b.manifest.version, undefined, { numeric: true })).at(-1);
        if (!latest)
            throw new Error('NOT_FOUND');
        return latest;
    }
    resolve(req) {
        const signed = this.get(req.productId, req.version);
        const m = signed.manifest;
        const capability = req.consumer?.capability;
        const iface = m.interfaces?.find(i => (!req.consumer?.interface || i.type === req.consumer.interface) && (!capability || i.capabilities?.includes(capability)));
        const artifact = req.consumer?.target ? m.artifacts?.find(a => a.target === req.consumer?.target) : undefined;
        return { manifest: m, selected: iface ? { type: iface.type, uri: iface.uri } : artifact ? { target: artifact.target, uri: artifact.uri, digest: artifact.digest } : undefined };
    }
}
