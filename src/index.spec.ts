import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: "RS256",
};
const currentTime = Math.round(Date.now() / 1000);
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
};

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  test("should add a user object containing the token claims to the request and call next", async () => {
    const res = createResponse();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    expect(req).toHaveProperty("user", claims);
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe("A request without a valid access token", () => {
  test("should return a 401 response and not call next if no authorization header is provided", async () => {
    const res = createResponse();
    res.send = jest.fn();
    const next = jest.fn();
    const req = createRequest({
      headers: {},
    });

    await authorise(options)(req, res, next);

    expect(res.send).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("should return a 401 response and not call next if token is not valid", async () => {
    const res = createResponse();
    res.send = jest.fn();
    const next = jest.fn();
    const req = createRequest({
      headers: {
        Authorization: `Bearer invalidToken`,
      },
    });

    await authorise(options)(req, res, next);

    expect(res.send).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test("should return a 401 response and not call next if token has expired", async () => {
    const res = createResponse();
    res.send = jest.fn();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT({
      ...claims,
      exp: currentTime,
    });
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);

    expect(res.send).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("For an invalid publicKey reponse", () => {
  beforeEach(async () => {
    nock.restore();

    nock(options.issuer)
      .persist()
      .get("/.well-known/jwks.json")
      .reply(200, { keys: [{ property: "notAValidPublicKey" }] });
  });

  test("should throw an error and not call next or res.send", async () => {
    const res = createResponse();
    res.send = jest.fn();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await expect(authorise(options)(req, res, next)).rejects.toThrow();

    expect(res.send).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });
});
