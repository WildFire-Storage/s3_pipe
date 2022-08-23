# s3_pipe
A python program that lets you direct stdin/stdout to/from S3 pipes.

## Usage:

```
s3_pipe.py put bucket_name object_key {-q}
s3_pipe.py get bucket_name object_key {-q}
s3_pipe.py createbucket bucket_name
s3_pipe.py deletebucket bucket_name
s3_pipe.py list bucket_name
s3_pipe.py listall
```

## Example:

### Save tar archive to remote S3 bucket:

```
tar cf - -C path_to_root . | s3_pipe.py put bucket_name object_key
```

### Adding compression and encryption

```
tar cf - -C path_to_root . | pigz -c 4 | openssl aes-256-cbc -e -in - -out - -pass pass:YourCyprtoKey | s3_pipe.py put bucket_name object_key
```

### Extract from S3 bucket:

```
s3_pipe.py get bucket_name object_key | tar xf - -C path_to_root
```

## Config file:  /etc/s3_pipe.conf

JSON file:

* "engine":  Choose the S3 transfer "engine".  Choices are "boto3" and "raw".
* "service":  Optional.  "aws" will use defaults for AWS.  "b2" will use defaults for BackBlase B2.
* "region":  Default region to create buckets in.
* "part_size":  Size of a "part" for multi-part objects.  Defaults to 67108864 (64 MB).
* "max_put":  Maximum number of parts that are "put" concurrently.  Defaults to 1.
* "aws_access_key_id":  Your access key id.  Optional if you are using boto3 and AWS and have AWS CLI configured.
* "aws_secret_access_key":  Your secret key.  Optional if you are using boto3 and AWS and have AWS CLI configured.
