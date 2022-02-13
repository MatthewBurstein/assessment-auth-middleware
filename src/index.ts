import { Algorithm, JsonWebTokenError, JwtPayload, verify } from "jsonwebtoken";
import * as express from "express";
import axios, { AxiosResponse } from "axios";
import jwkToPem from "jwk-to-pem";

declare module "express" {
  interface Request {
    user?: JwtPayload;
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
    const authToken = extractAuthToken(req);

    if (authToken) {
      try {
        const publicKey = await getPublicKey();
        req.user = verifyJwt(authToken, publicKey, options);
        return next();
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
  };

const extractAuthToken = (req: express.Request): string | undefined =>
  req.headers?.authorization?.substring("Bearer ".length);

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
    algorithms: [options.algorithms as Algorithm], // this cast is safe because a string which is not an Algorithm will just fail the verification
    audience: options.audience,
    issuer: options.issuer,
  });
  if (isString(result)) {
    throw new JsonWebTokenError("jwt malformed");
  }
  return result;
};

const isString = (value: any): value is string => typeof value === "string";

export default authorize;
