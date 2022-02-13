import { JwtPayload } from "jsonwebtoken";
import axios, { AxiosResponse } from "axios";

const PUBLIC_KEY_URL = "http://issuer.com/.well-known/jwks.json";

interface PublicKeyResponse {
  keys: [Record<string, unknown>];
}

export const getPublicKey = async (): Promise<JwtPayload> => {
  const publicKeyResponse: AxiosResponse<PublicKeyResponse> =
    await axios.get<PublicKeyResponse>(PUBLIC_KEY_URL);
  // TODO what happens if there are multiple keys or no key?;
  return publicKeyResponse.data.keys[0];
};
