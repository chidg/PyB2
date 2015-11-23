# PyB2
Backblaze B2 API wrapper in Python

Currently supports creation and listing of B2 Buckets.
Lots to do.

How to use:
- Fork repo (or download files) and `pip install requirements.txt`
- Set your B2 Account ID and Authentication Key in b2_api.py
- Instantiate a B2 object. On init, it will authenticate with the API. `b2 = B2()`
- Call `b2.get_buckets()` to get existing buckets in B2 or `b2.create_bucket('bucketname', 'allPublic')` to create a bucket.
