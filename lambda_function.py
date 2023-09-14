import jwt
import requests
import json
import os
from jwt.algorithms import RSAAlgorithm

# Get Cognito pool URL and audience from Lambda environment variables
COGNITO_POOL_URL = os.environ['COGNITO_POOL_URL']
COGNITO_APP_CLIENT_ID = os.environ['COGNITO_APP_CLIENT_ID']
COGNITO_POOL_PUBLIC_KEY_URL = COGNITO_POOL_URL + '/.well-known/jwks.json'


def lambda_handler(event, context):
    token = event['userToken']  # Assuming the token is passed in the event
    
    # Get Cognito's public keys
    keys = requests.get(COGNITO_POOL_PUBLIC_KEY_URL).json()['keys']
    
    # Try to decode the token using each key
    decoded_token = None
    for key in keys:
        try:
            decoded_token = jwt.decode(
                token,
                RSAAlgorithm.from_jwk(json.dumps(key)),
                algorithms=['RS256'],
                audience=COGNITO_APP_CLIENT_ID,
                issuer=COGNITO_POOL_URL
            )
            break
        except jwt.DecodeError:
            continue

    if decoded_token:
        user_id = decoded_token['sub']  # 'sub' claim is the standard claim for the unique user identifier in Cognito
        return {'userId': user_id}
    else:
        raise Exception('Invalid token or unauthorized')


