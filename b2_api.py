import base64
import requests

# Settings
URLS = {
    'authorise_account_url': 'https://api.backblaze.com/b2api/v1/b2_authorize_account',
    'get_upload_url_url_suffix': '/b2api/v1/b2_get_upload_url',
    'list_buckets_url_suffix': '/b2api/v1/b2_list_buckets',
    'create_bucket_url_suffix': '/b2api/v1/b2_create_bucket'
}

B2_ACCOUNT_ID = b'YOUR ID'
B2_ACCOUNT_KEY = b'YOUR KEY'


class B2(object):

    def __init__(self, *args, **kwargs):
        self.auth_token = None
        self.api_url = None
        self.download_url = None
        self.buckets = []
        self.authorise_account()

    def authorise_account(self):
        id_and_key = base64.b64encode(B2_ACCOUNT_ID + b':' + B2_ACCOUNT_KEY)
        basic_auth_string = b'Basic ' + id_and_key
        headers = {'Authorization': basic_auth_string}
        r = requests.get(URLS['authorise_account_url'], headers=headers)
        response_data = r.json()
        if r.status_code == 200:
            self.auth_token = response_data['authorizationToken']
            self.api_url = response_data['apiUrl']
            self.download_url = response_data['downloadUrl']
            print('Authenticated successfully')
        else:
            raise Exception(r.text)

    def get_buckets(self):
        if self.api_url is None or self.auth_token is None:
            raise Exception('sorry, you need to authorise the account before you do anything else')
        r = requests.get('{}{}'.format(self.api_url, URLS['list_buckets_url_suffix']),
                params={'accountId' : B2_ACCOUNT_ID},
                headers={'Authorization': self.auth_token}
            )
        if r.status_code == 200:
            for bucket in r.json()['buckets']:
                new_bucket = B2Bucket(self, **bucket)
                if new_bucket not in self.buckets:
                    self.buckets.append(new_bucket)
        else:
            raise Exception(r.text)

    def get_bucket_by_name(self, name):
        if self.buckets:
            for bucket in self.buckets:
                if bucket.bucket_name == name:
                    return bucket

    def list_buckets(self):
        if self.buckets:
            for bucket in self.buckets:
                print(str(bucket))

    def create_bucket(self, bucket_name, bucket_type):
        new_bucket = B2Bucket(self, bucketId=None, bucketName=bucket_name, bucketType=bucket_type)
        self.buckets.append(new_bucket)



class B2Bucket(object):

    def __init__(self, b2, *args, bucketId=None, bucketName=None, bucketType='allPrivate', **kwargs):
        self.b2 = b2
        self.bucket_name = bucketName
        self.bucket_type = bucketType
        if bucketId is not None:
            self.bucket_id = bucketId
        else:
            self.bucket_id = self.create()
        self.upload_url = self.get_upload_url()

    def create(self):
        # TODO: Regex validation for acceptable bucket_name
        if len(self.bucket_name) < 6 or len(self.bucket_name) > 50:
            raise Exception('Bucket names need to be at least 6 characters and no greater than 50 characters long.')
        if self.bucket_type not in ['allPrivate', 'allPublic']:
            raise Exception('Bucket type may only be "allPrivate" or "allPublic"')

        r = requests.get('{}{}'.format(self.b2.api_url, URLS['create_bucket_url_suffix']),
                params = {
                    'accountId': B2_ACCOUNT_ID,
                    'bucketName': self.bucket_name,
                    'bucketType': self.bucket_type
                },
                headers={'Authorization': self.b2.auth_token}
            )
        if r.status_code == 200:
            return r.json()['bucketId']
        else:
            raise Exception(r.text)

    def get_upload_url(self):
        if self.b2.api_url is None or self.b2.auth_token is None:
            raise Exception('sorry, you need to authorise the account before you do anything else')
        r = requests.get('{}{}'.format(self.b2.api_url, URLS['get_upload_url_url_suffix']),
                params={'bucketId' : self.bucket_id},
                headers={'Authorization': self.b2.auth_token}
            )
        if r.status_code == 200:
            return r.json()['uploadUrl']
        else:
            raise Exception(r.text)

    def __str__(self):
        return "bucket id: {}, bucket name: {}, bucket type: {}".format(
            self.bucket_id,
            self.bucket_name,
            self.bucket_type
        )

