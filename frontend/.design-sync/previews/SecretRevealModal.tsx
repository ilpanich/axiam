import type { ReactNode } from "react";
import { SecretRevealModal } from "frontend";

/**
 * SecretRevealModal renders `position: fixed; inset: 0`. The `transform` on this
 * wrapper makes it the containing block for fixed-position descendants (CSS
 * Transforms spec), trapping the real modal — backdrop, blur and all — inside
 * the preview cell instead of letting it cover the whole sheet.
 */
function Stage({ children, height = 520 }: { children: ReactNode; height?: number }) {
  return (
    <div
      style={{
        position: "relative",
        transform: "translateZ(0)",
        height,
        width: "100%",
        overflow: "hidden",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.08)",
        background: "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)",
      }}
    >
      {children}
    </div>
  );
}

const noop = () => {};

export function OAuth2ClientCredentials() {
  return (
    <Stage>
      <SecretRevealModal
        open
        onClose={noop}
        title="OAuth2 client registered"
        description="acme-portal — Authorization Code + PKCE, confidential client."
        secrets={[
          { label: "Client ID", value: "cl_7f3a91c04b2e4d18a6e0d5c9b1f2a730" },
          {
            label: "Client secret",
            value: "cs_live_9Qk2pR7vNxT4mZbW8sYcJ1hLdE6uA3fGoP0iVrXn",
          },
        ]}
      />
    </Stage>
  );
}

export function ServiceAccountKey() {
  return (
    <Stage>
      <SecretRevealModal
        open
        onClose={noop}
        title="Service account key issued"
        description="ci-deploy-bot — tenant acme-prod. Store this in your pipeline's secret manager."
        secrets={[
          { label: "Key ID", value: "sak_01J8ZQ4C7N9M2XB5RTKD3PWVH6" },
          {
            label: "Secret key",
            value: "axm_sk_prod_4hT9dLpQ2vRz7XwK1nYcB8mJfS3gU6eA0iOtZrVyNqMxCbDl",
          },
          { label: "Expires", value: "2027-01-14 09:32 UTC (180 days)", mono: false },
        ]}
      />
    </Stage>
  );
}

export function CertificatePrivateKey() {
  return (
    <Stage height={600}>
      <SecretRevealModal
        open
        onClose={noop}
        title="Device certificate issued"
        description="iot-gateway-04.acme-prod — Ed25519, signed by the acme organization CA. The private key is never stored by AXIAM."
        secrets={[
          {
            label: "SHA-256 fingerprint",
            value: "3f:a9:1c:7e:04:b2:88:d5:6a:11:c3:9e:0f:47:bd:52",
          },
          {
            label: "Private key (PKCS#8, PEM)",
            value:
              "-----BEGIN PRIVATE KEY-----\n" +
              "MC4CAQAwBQYDK2VwBCIEIL9kM2xQ0v7ZpR3nHsWc6Ub1TfKdA8yEjXmNoPqRsTuV\n" +
              "-----END PRIVATE KEY-----",
          },
        ]}
      />
    </Stage>
  );
}
