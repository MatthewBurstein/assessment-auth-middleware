# Collective Benefits Tech Assessment

Our platform is comprised of a set of single-page web applications interacting with backend microservices through REST APIs.
We use AWS Cognito for authentication and authorisation, which follows the OAuth 2.0 standard.
Users authenticate with AWS Cognito and the web applications ultimately receive an access token in the form of a JWT to authorise the user to access our backend APIs.
The `sub` claim contained in the encoded and digitally signed access token identifies the user intending to access the API.

In this exercise, you will create a Node.js Express middleware package to be consumed by our microservices to validate the access token and read out the user ID.
The middleware should meet the following acceptance criteria:

* For a valid token, it should add a `user` field to the request object containing all claims, and then delegate to the next middleware.
* For an invalid token, it should end the request-response cycle by returning a 401 response.
* It should confirm the structure of the JWT, validate the JWT signature, and verify the claims, as described in this article: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html.

We intend to use the `verify` function of the `jsonwebtoken` NPM package to do much of the heavy-lifting (https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback).

HINT: you might be best using the alternative `decode` function provided by `jsonwebtoken` to get started (https://www.npmjs.com/package/jsonwebtoken#jwtdecodetoken--options).

A failing "happy path" test has already been set up for you, including a mock response for the request to retrieve the public key used to verify the token signature.

## Notes

* There is a disconnect between the type of the `Request` interface in `index.ts` and the expected `user` field in the tests.
  The type seems to want the overload of verify with `complete: true`. I assumed the tests were correct and amended the type.
* The `algorithms` property on the `Options` interface is a string, but the algorithms in `verify` is a string array.
  I have handled the algorithms property as though it were a single algorithm as a string, but since the word is plural I wonder if
  it is actually eg a comma separated list in which case I would split it into a `string[]` to pass to the verify options.
