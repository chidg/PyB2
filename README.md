# PyB2
Backblaze B2 API wrapper in Python

Currently supports creation and listing of B2 Buckets.
Lots to do.

How to use:
- Fork repo (or download files) and `pip install -r requirements.txt`
- Set your B2 Account ID and Authentication Key in b2_api.py
- Instantiate a B2 object. On init, it will authenticate with the API. `b2 = B2()`
- Call `b2.get_buckets()` to get existing buckets in B2 or `b2.create_bucket('bucketname', 'allPublic')` to create a bucket.
- Upload a file to a bucket with `bucket_instance.upload_file('path/to/file')`
- Access the list of existing files in a bucket with `bucket_instance.get_files()` (Backblaze pagination function not implemented yet).
