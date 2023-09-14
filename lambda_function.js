const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const https = require('https');

const COGNITO_POOL_URL = process.env.COGNITO_POOL_URL; 
const COGNITO_POOL_PUBLIC_KEY_URL = `${COGNITO_POOL_URL}/.well-known/jwks.json`;

exports.lambda_handler = async (event) => {
    const token = event.userToken;  // Extracting token from event.userToken

    try {
        const jwks = await getJWKS();
        const pem = jwkToPem(jwks.keys[0]); // Convert the JWK to PEM format
        const decodedToken = jwt.verify(token, pem, { algorithms: ['RS256'] });

        return {
            statusCode: 200,
            body: JSON.stringify({ userId: decodedToken.sub })
        };
    } catch (err) {
        console.error('Failed to decode or verify token:', err);
        return {
            statusCode: 401,
            body: JSON.stringify({ error: 'Invalid token or unauthorized' })
        };
    }
};

function getJWKS() {
    return new Promise((resolve, reject) => {
        https.get(COGNITO_POOL_PUBLIC_KEY_URL, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                resolve(JSON.parse(data));
            });

        }).on('error', (err) => {
            reject(err);
        });
    });
}
