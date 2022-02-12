import {
  Jwt,
  JwtPayload,
  verify,
  Algorithm,
  JsonWebTokenError,
} from "jsonwebtoken";
import * as express from "express";
import axios, { AxiosResponse } from "axios";
import jwkToPem from "jwk-to-pem";

declare module "express" {
  interface Request {
    user?: Jwt;
  }
}

interface PublicKeyResponse {
  keys: [Record<string, unknown>];
}

export interface Options {
  issuer: string;
  audience: string;
  algorithms: string;
}

const authorize =
  (options: Options) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void | express.Response> => {
    const authorizationHeader = req.headers.authorization;

    if (authorizationHeader) {
      const authorization = authorizationHeader.substring("Bearer ".length);
      const publicKey = await getPublicKey();
      try {
        verifyJwt(authorization, publicKey, options);
      } catch (err) {
        if (err instanceof JsonWebTokenError) {
          return res.send(401);
        } else {
          throw err;
        }
      }
    } else {
      return res.send(401);
    }

    return Promise.reject("Not implemented");
  };

const getPublicKey = async (): Promise<JwtPayload> => {
  const publicKeyResponse: AxiosResponse<PublicKeyResponse> =
    await axios.get<PublicKeyResponse>(
      "http://issuer.com/.well-known/jwks.json"
    );
  // TODO what happens if there are multiple keys or no key?;
  return publicKeyResponse.data.keys[0];
};

const verifyJwt = (
  authorization: string,
  publicKey: JwtPayload,
  options: Options
): JwtPayload => {
  const result = verify(authorization, jwkToPem(publicKey), {
    algorithms: [options.algorithms as Algorithm],
    audience: options.audience,
    issuer: options.issuer,
  });
  // TODO what happens if result is string
  return result as JwtPayload;
};

export default authorize;
