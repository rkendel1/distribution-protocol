/**
 * Distribution Protocol — `registry://` artifact transport.
 *
 * A `registry://<digest>` location means "ask the registry this client is
 * already configured with for the bytes addressed by this digest". It is DERIVED
 * from the digest and never appears in a signed manifest, which is how location
 * stays out of artifact identity: the same release, with the same signature,
 * resolves to whichever registry or mirror the consumer chose.
 *
 * Like every transport, this one is trusted for availability only. Whatever it
 * streams is hashed by `acquireFromSource` and rejected unless it matches the
 * digest the publisher signed.
 */

import {
  PermanentTransportError,
  TransportError,
  ErrorCode,
} from '../../protocol/src/index.mjs';
import { isDigest } from '../../protocol/src/artifact.mjs';

/**
 * @param {{openArtifact: (digest: string) => Promise<{stream: AsyncIterable<Uint8Array>}>}} registry
 * @returns {import('../../protocol/src/transport.mjs').Transport}
 */
export function registryTransport(registry) {
  return {
    scheme: 'registry',
    canHandle: (uri) => /^registry:\/\//i.test(String(uri ?? '')),

    async acquire(uri) {
      const digest = decodeURIComponent(String(uri).slice('registry://'.length));
      if (!isDigest(digest)) {
        throw new PermanentTransportError(`registry location must name a sha256 digest, got ${uri}`, { uri });
      }
      let artifact;
      try {
        artifact = await registry.openArtifact(digest);
      } catch (err) {
        // Absent bytes will not appear on a retry; anything else (network,
        // 5xx) might.
        if (err?.code === ErrorCode.ARTIFACT_NOT_FOUND) {
          throw new PermanentTransportError(`registry has no bytes for ${digest}`, { uri, cause: err });
        }
        throw new TransportError(`registry failed to open ${digest}: ${err.message}`, { uri, cause: err });
      }
      return artifact.stream;
    },
  };
}
