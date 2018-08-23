from datetime import datetime, timedelta

from botocore import session
from botocore.signers import CloudFrontSigner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


REGION = 'ap-northeast-1'
PROFILE = 'default'
URL = 'https://example.com/index.html'
KEY_ID = 'xxxxxxxxxxx'
PRIVATE_KEY_PATH = './pk-xxxxxxxxxxxxxx.pem'
EXPIRE = 1


def get_rsa_signer(message):
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(
                data=f.read(),
                password=None,
                backend=default_backend(),
        )
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())


def main():
    sess = session.get_session()
    session.profile = SYSOP
    session.region = REGION

    # JST, not use timezone
    expire = datetime.now() + timedelta(minutes=EXPIRE) - timedelta(hours=9)

    cloudfront_signer = CloudFrontSigner(KEY_ID, get_rsa_signer)

    signed_url = cloudfront_signer.generate_presigned_url(
            URL,
            date_less_than=expire,
    )

    print(signed_url)


if __name__ == "__main__":
    main()
