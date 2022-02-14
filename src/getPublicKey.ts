import axios from "axios";

const PUBLIC_KEY_URL = "http://issuer.com/.well-known/jwks.json";

interface PublicKeyResponse {
  keys: [Record<string, unknown>];
}

export const getPublicKey = async (): Promise<Record<string, unknown>> => {
  const publicKeyResponse = await axios.get<PublicKeyResponse>(PUBLIC_KEY_URL);

  return publicKeyResponse.data.keys[0];
};
