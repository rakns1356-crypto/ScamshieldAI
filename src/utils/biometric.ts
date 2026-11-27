const VAULT_STORAGE_KEY = 'scamshield_vault_config_v1';

export interface VaultConfig {
  enabled: boolean;
  mode: 'webauthn' | 'pin';
  credentialId?: string;
  pinHash?: string;
  pinSalt?: string;
  updatedAt: string;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToUint8Array(base64Url: string): Uint8Array {
  const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}

async function hashPin(pin: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(`${salt}:${pin}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bufferToBase64Url(digest);
}

export function loadVaultConfig(): VaultConfig | null {
  try {
    const raw = localStorage.getItem(VAULT_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as VaultConfig;
  } catch {
    return null;
  }
}

export function clearVaultConfig(): void {
  localStorage.removeItem(VAULT_STORAGE_KEY);
}

export async function isPlatformBiometricAvailable(): Promise<boolean> {
  try {
    if (
      typeof window === 'undefined' ||
      !window.PublicKeyCredential ||
      typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function'
    ) {
      return false;
    }
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function enrollBiometricPasskey(): Promise<{ ok: true; config: VaultConfig } | { ok: false; error: string }> {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'ScamShield AI Privacy Vault',
        },
        user: {
          id: userId,
          name: 'scamshield-vault-user',
          displayName: 'ScamShield Protected User',
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        },
        timeout: 45000,
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { ok: false, error: 'Biometric setup was cancelled.' };
    }

    const config: VaultConfig = {
      enabled: true,
      mode: 'webauthn',
      credentialId: bufferToBase64Url(credential.rawId),
      updatedAt: new Date().toISOString(),
    };
    localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(config));
    return { ok: true, config };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Biometric sensor is unavailable in this preview frame.';
    return {
      ok: false,
      error: `${message} You can use a 4-digit Device Vault PIN instead.`,
    };
  }
}

export async function verifyBiometricPasskey(config: VaultConfig): Promise<{ ok: boolean; error?: string }> {
  try {
    if (!config.credentialId) {
      return { ok: false, error: 'Saved biometric key not found.' };
    }
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credIdBytes = base64UrlToUint8Array(config.credentialId);

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: 'public-key',
            id: credIdBytes.buffer as ArrayBuffer,
          },
        ],
        userVerification: 'required',
        timeout: 45000,
      },
    });

    return { ok: Boolean(assertion) };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'Biometric verification was cancelled or failed.',
    };
  }
}

export async function enrollVaultPin(pin: string): Promise<VaultConfig> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = bufferToBase64Url(saltBytes.buffer);
  const pinHash = await hashPin(pin, salt);
  const config: VaultConfig = {
    enabled: true,
    mode: 'pin',
    pinHash,
    pinSalt: salt,
    updatedAt: new Date().toISOString(),
  };
  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(config));
  return config;
}

export async function verifyVaultPin(pin: string, config: VaultConfig): Promise<boolean> {
  if (!config.pinHash || !config.pinSalt) return false;
  const computed = await hashPin(pin, config.pinSalt);
  return computed === config.pinHash;
}
