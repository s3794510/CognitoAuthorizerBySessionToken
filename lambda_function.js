const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const https = require('https');

const COGNITO_POOL_URL = process.env.COGNITO_POOL_URL; 
const COGNITO_POOL_PUBLIC_KEY_URL = `${COGNITO_POOL_URL}/.well-known/jwks.json`;

exports.lambda_handler = async (event) => {
    const authHeader = event.headers.Authorization || event.headers.authorization; // Headers may be case-sensitive

    if (!authHeader) {
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Authorization header is missing' })
        };
    }   

    // Extract the token from the Authorization header
    const token = authHeader.split(' ')[1]; // Assumes "Bearer YOUR_TOKEN_HERE" format

    // Now, you can use the token for your logic, like verifying it
    //console.log('Extracted Token:', token);
    
    // Check if the token is blank, null, or undefined
    // if (!token || token.trim() === '' || typeof token === 'undefined') {
    //     return {
    //         statusCode: 401,
    //         body: JSON.stringify({ 
    //             error: 'Token is blank, null, or undefined',
    //             token: token
    //         })
    //     };
    // }
    
    try {
        const jwks = await getJWKS();
        const pem = jwkToPem(jwks.keys[0]); // Convert the JWK to PEM format
        const decodedToken = jwt.verify(token, pem, { algorithms: ['RS256'] });

        return {
            statusCode: 200,
            body: JSON.stringify(decodedToken)
        };
    } catch (err) {
        console.error('Failed to decode or verify token:', err);
        return {
            statusCode: 401,
            body: JSON.stringify({ 
                error: 'Invalid token or unauthorized',
                token: token  // Adding the token to the error response
            })
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
