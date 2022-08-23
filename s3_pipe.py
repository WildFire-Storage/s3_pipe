#!/usr/bin/python3.9

if True:
    import sys
    import json, xmltodict
    import argparse
    import hashlib, urllib
    import base64, hmac, hashlib, datetime, time
    import io, os
    import munch
    import requests
    from copy import deepcopy
    from inspect import getframeinfo, stack
    from multiprocessing import Process, Manager

    WHITE =u'\u001b[37m'
    CYAN  =u'\u001b[36m'

if __name__ == "__main__":
    if os.path.exists('/etc/s3_pipe.conf'):
        with open('/etc/s3_pipe.conf', 'r') as fh:
            config = json.load(fh)
    else:
        config = { 'engine': 'boto3',
                'region': 'us-east-1',
                'auth'  : 'aws' }

    if not config.get('part_size'):
        config['part_size'] = 64 * 1024 * 1024
    if not config.get('max_put'):
        config['max_put'] = 1

    if config['engine'] == 'boto3':
        import boto3
        from botocore.config import Config
    elif config['engine'] == 'raw':
        import requests
    else:
        sys.stderr.write('"engine" is not valid in config file.\n')
        exit(1)

def tr(msg):
    try:
        caller = getframeinfo(stack()[1][0])
        fname = caller.filename.split('/')[-1]
        fname = fname.split('.')[0]
        function = caller.function
        lineno = caller.lineno
    except:
        caller = "?"
        fname  = "?"
        function = "?"
        lineno = 0
    sys.stderr.write( f'{CYAN}[{fname:<18}:{lineno:>4} {function:<15}] {msg}\n{WHITE}')
    sys.stderr.flush()

class s3_raw(object):
    def __init__(self):

        t = datetime.datetime.utcnow()
        self.amzdate   = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d')

        if config['service'] == 'aws': self.set_aws()
        elif config['service'] == 'b2': self.set_b2()
    def set_b2(self):
        try:
            with open('/etc/s3_pipe_b2.conf', 'r') as fh:
                self.conf = json.load(fh)
        except: pass
        self.service  = 's3'
        self.svc_host = 's3.us-west-001.backblazeb2.com'
        self.region   = config.get('region','us-west-001')

        self.access_key = self.conf['aws_access_key_id']
        self.secret_key = self.conf['aws_secret_access_key']
    def set_aws(self):
        try:
            with open('/etc/s3_pipe_aws.conf', 'r') as fh:
                self.conf = json.load(fh)
        except: pass
        self.service  = 's3'
        self.svc_host = 's3.amazonaws.com'
        self.region   = config.get('region','us-east-1')

        self.access_key = self.conf['aws_access_key_id']
        self.secret_key = self.conf['aws_secret_access_key']
    def _sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    def _getSignatureKey(self, key, dateStamp, regionName, serviceName):
        kDate = self._sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = self._sign(kDate, regionName)
        kService = self._sign(kRegion, serviceName)
        kSigning = self._sign(kService, 'aws4_request')
        return kSigning
    def __request(self, xml=True):

        if self.method in ( 'GET' , 'DELETE' ): self.data = b''
        endpoint = f'https://{self.host}{self.canonical_url}'
        payload_hash = hashlib.sha256(self.data).hexdigest()
        canonical_querystring = self.request_parameters
        canonical_headers  = 'host:' + self.host + '\n'
        canonical_headers += 'x-amz-content-sha256:' + payload_hash + '\n'
        canonical_headers += 'x-amz-date:' + self.amzdate + '\n'
        signed_headers     = 'host;x-amz-content-sha256;x-amz-date'

        canonical_request  = self.method           + '\n'
        canonical_request += self.canonical_url    + '\n'
        canonical_request += canonical_querystring + '\n'
        canonical_request += canonical_headers     + '\n'
        canonical_request += signed_headers        + '\n'
        canonical_request += payload_hash

        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = self.datestamp + '/' + self.region + '/' + self.service + '/' + 'aws4_request'
        string_to_sign = algorithm + '\n' +  self.amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        signing_key = self._getSignatureKey(self.secret_key, self.datestamp, self.region, self.service)
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = algorithm + ' ' + 'Credential=' + self.access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

        self.headers = { 'x-amz-date'          : self.amzdate.encode        ('utf-8'),
                         'x-amz-content-sha256': payload_hash.encode        ('utf-8'),
                         'Authorization'       : authorization_header.encode('utf-8') }

        if canonical_querystring:
            self.request_url = endpoint + '?' + canonical_querystring
        else:
            self.request_url = endpoint

        if self.method == 'GET':
            r = requests.get(self.request_url, headers = self.headers)
        elif self.method == 'POST':
            r = requests.post(self.request_url, headers = self.headers, data=self.data)
        elif self.method == 'PUT':
            r = requests.put(self.request_url, headers = self.headers, data=self.data)
        elif self.method == 'DELETE':
            r = requests.delete(self.request_url, headers = self.headers)
        else:
            die()

        try:
            if xml:
                rr = xmltodict.parse(r.text)
            else:
                rr = r.content
            return rr
        except:
            return None
    def _request(self, xml=True):
        try:
            return self.__request(xml=xml), True
        except:
            print('Request Error.', file=sys.stderr)
            exit(1)
    def GetBuckets(self):

        self.method             = 'GET'
        self.canonical_url      = '/'
        self.request_parameters = ''
        self.host               = self.svc_host

        rr = []
        try:
            r,err = self._request()
            buckets = r['ListAllMyBucketsResult']['Buckets']['Bucket']
            if not type(buckets) is list: buckets = [ buckets ]
            for x in buckets:
                rr.append(x['Name'])
        except: pass
        return rr
    def GetKeys(self, bucket_name):

        self.method        = 'GET'
        self.canonical_url = '/'
        req                = ''
        self.host          = bucket_name + '.' + self.svc_host

        rr = []
        token = None
        while True:
            if token:
                self.request_parameters = 'marker=' + token + '&' + req
            else:
                self.request_parameters = req

            try:
                r,err = self._request()
                res = r['ListBucketResult']
                contents = res.get('Contents')
                if contents:
                    if not type(contents) is list: contents = [ contents ]
                    for x in contents:
                        rr.append( {'key': x['Key'], 'size': int(x['Size']) } )
                token = rr[-1]['key'] if res.get('IsTruncated') == "true" else None
            except: break

            if not token: break

        return rr
    def CreateBucket(self, bucket_name):
        self.method             = 'PUT'
        self.canonical_url      = '/'
        self.request_parameters = ''
        self.host               = bucket_name + '.' + self.svc_host
        data  = f'<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n'
        data += f'   <LocationConstraint>{config["region"]}</LocationConstraint>'
        data += f'</CreateBucketConfiguration>'
        self.data = data.encode('utf-8')

        return self._request()
    def DeleteBucket(self, bucket_name):
        self.method             = 'DELETE'
        self.canonical_url      = '/'
        self.request_parameters = ''
        self.host               = bucket_name + '.' + self.svc_host

        return self._request()
    def GetObject(self, bucket_name, object_key):

        self.method        = 'GET'
        self.canonical_url = '/' + object_key
        req                = ''
        self.host          = bucket_name + '.' + self.svc_host

        self.request_parameters = req

        rr = self._request(xml=False)
        return rr
    def PutObject(self, bucket_name, object_key, data):

        self.method        = 'PUT'
        self.canonical_url = '/' + object_key
        req                = ''
        self.host          = bucket_name + '.' + self.svc_host
        self.data          = data

        self.request_parameters = req

        res,err = self._request(xml=True)
        return res
    def DeleteObject(self, bucket_name, object_key):
        self.method             = 'DELETE'
        self.cononical_url      = '/' + object_key
        self.request_parameters = ''
        self.host               = bucket_name + '.' + self.svc_host

        return self._request()
class s3_boto(object):
    def __init__(self):

        self.s3_client   = boto3.client('s3')
        self.s3_resource = boto3.resource('s3')
        self.bucket_name = ""
        self.object_id   = ""
        self.region      = None

        self.conf        = { 'service'              : 'aws',
                             'endpoint_url'         : None,
                             'aws_access_key_id'    : None,
                             'aws_secret_access_key': None }
        try:
            with open('/etc/s3_pipe.conf', 'r') as fh:
                self.conf = json.load(fh)
        except: pass

        self.s3_config = None
        if self.conf['service'] == 'b2':
            if not self.conf.get('endpoint_url'): self.conf['endpoint_url'] = 'https://s3.us-west-001.backblazeb2.com'
            self.s3_config = Config(signature_version='s3v4')

        self.conf = munch.Munch(self.conf)

        if not self.s3_config:
            if not self.conf.endpoint_url:
                if not self.conf.aws_access_key_id:
                    self.s3_client   = boto3.client  ('s3')
                    self.s3_resource = boto3.resource('s3')
                else:
                    self.s3_client   = boto3.client  ('s3', aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
                    self.s3_resource = boto3.resource('s3', aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
            else:
                if not self.conf.aws_access_key_id:
                    self.s3_client   = boto3.client  ('s3', endpoint_url=self.conf.endpoint_url)
                    self.s3_resource = boto3.resource('s3', endpoint_url=self.conf.endpoint_url)
                else:
                    self.s3_client   = boto3.client  ('s3', endpoint_url=self.conf.endpoint_url, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
                    self.s3_resource = boto3.resource('s3', endpoint_url=self.conf.endpoint_url, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
        else:
            if not self.conf.endpoint_url:
                if not self.conf.aws_access_key_id:
                    self.s3_client   = boto3.client  ('s3', config=self.s3_config)
                    self.s3_resource = boto3.resource('s3', config=self.s3_config)
                else:
                    self.s3_client   = boto3.client  ('s3', config=self.s3_config, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
                    self.s3_resource = boto3.resource('s3', config=self.s3_config, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
            else:
                if not self.conf.aws_access_key_id:
                    self.s3_client   = boto3.client  ('s3', config=self.s3_config, endpoint_url=self.conf.endpoint_url)
                    self.s3_resource = boto3.resource('s3', config=self.s3_config, endpoint_url=self.conf.endpoint_url)
                else:
                    self.s3_client   = boto3.client  ('s3', config=self.s3_config, endpoint_url=self.conf.endpoint_url, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
                    self.s3_resource = boto3.resource('s3', config=self.s3_config, endpoint_url=self.conf.endpoint_url, aws_access_key_id=self.conf.aws_access_key_id, aws_secret_access_key=self.conf.aws_secret_access_key)
    def GetBuckets(self):
        rr = []
        for bucket in self.s3_resource.buckets.all():
            rr.append(bucket.name)
        return rr
    def GetKeys(self, bucket_name):
        rr = []
        for obj in self.s3_resource.Bucket(bucket_name).objects.all():
            rr.append( {'key': obj.key, 'size': obj.size } )
        return rr
    def CreateBucket(self, bucket_name):
        self.s3_client.create_bucket(Bucket=bucket_name)
    def DeleteBucket(self, bucket_name):
        self.s3_client.delete_bucket(Bucket=Bucket_name)
    def GetObject(self, bucket_name, object_key):
        obj = self.s3_resource.Object(bucket_name, object_key).get()
        return obj['Body'].read()
    def PutObject(self, bucket_name, object_key, data):
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=data)
    def DeleteObject(self, bucket_name, object_key):
        self.s3_resource.Object(bucket_name, object_key).delete()
class mul_cmd(object):
    def __init__(self):
        self.manager = Manager()
        self.pp = []
    def _save_p(self, p):
        for n in range(len(self.pp)):
            if not self.pp[n] is None: continue
            self.pp[n] = p;
            return
        self.pp.append(p)
    def _job_cnt(self):
        cnt = 0;
        for p in self.pp:
            cnt += p.is_alive()
        return cnt
    def _wait_for_jobs(self):
        while self._job_cnt():
            time.sleep(0.1)
    def _get_obj(self, r):
        res,err = ops['GetObject'](r['bucket_name'],r['id'])
        r['rr'] = json.loads(res)
        return
        print( f'{r["n"]}: start' )
        retry_cnt = 0
        while retry_cnt < 5:
            try:
                r['rr'] = json.loads(ops['GetObject'](r['bucket_name'],r['id']))
                #print( f'{r["n"]}  retry_cnt = {retry_cnt}: done' )
                return
            except:
                retry_cnt += 1

        r['rr'] = {}
        return
    def get_objs(self, bucket_name, ids):
        vv = []

        for n in range(len(ids)):
            v0 = { 'n'          : n,
                   'bucket_name': bucket_name,
                   'id'         : ids[n] }
            v = self.manager.dict(v0)
            vv.append(v)
            p = Process(target=mul_cmd()._get_obj, args=(v,))
            p.start()

            self.pp.append(p)

            while self._job_cnt() >= 50:
                time.sleep(0.1)

        rr = []
        for n in range(len(ids)):
            r  = self.pp[n].join()
            rr.append(vv[n]['rr'])

        return rr
    def _job_cnt(self):
        cnt = 0;
        for p in self.pp:
            cnt += p.is_alive()
        return cnt
    def put_obj(self, bucket_name, id, data):
        p = Process(target=ops['PutObject'], args=(bucket_name, id, data) )
        self.pp.append(p)
        p.start()
class s3_cmd(object):
    def __init__(self):
        self.tm0 = int(time.time()*1000)
    def PrettyNum(self, n):
        if n < 10000: return f'{n:>4}B'
        for t in ( 'K','M','G','T','P','E' ):
            n = n / 1024
            if n < 10000: return f'{n:>4.0f}{t}'
        die()
    def PrettyTime(self, n):
        n = n / 1000
        if n < 100: return f'{n:>4.1f} sec'
        n = n / 60
        if n < 100: return f'{n:>4.1f} min'
        n = n / 60
        if n < 100: return f'{n:>4.1f}  hr'
        n = n / 24
        if n < 100: return f'{n:>4.1f} day'
        n = n / 30
        if n < 100: return f'{n:>4.1f} mon'
        n = n / 365
        if n < 100: return f'{n:>4.1f}  yr'
        die()
    def _disp_list_hdrs(self):
        print( f'{"Bucket Name":<30} {"Obj Name":<20}  {"Obj Tot Size":>16} {"":>5} {"Parts":>6}' )
    def _disp_bucket(self, bucket_name):
        cnt = 0
        keys = ops['GetKeys'](bucket_name)
        ids = []
        for key in keys:
            id0 = key['key']
            if not id0.endswith('-s3_pipe'): continue
            ids.append(id0)

        rrs = mul_cmd().get_objs(bucket_name, ids)
        for n in range(len(ids)):
            id = ids[n]
            id = id[0:len(id)-8]
            rr = rrs[n]
            print( f'{bucket_name:<30} {id:<20}  {rr["tot_size"]:>16,} {self.PrettyNum(rr["tot_size"])} {rr["part_cnt"]:>6}' )
            cnt += 1

        if not cnt:
            print( f'{bucket_name:<30} no objects' )
    def _cmd_listbucket(self, bucket_name):
        cnt = 0
        keys = ops['GetKeys'](bucket_name)
        for key in keys:
            if not key['key'].endswith('-s3_pipe'): continue
            id = key['key'][:0:-8]
            cnt += 1
            print( f'{bucket_name:<30} {id:<20}  {key["tot_size"]:>12} {key["part_cnt"]:>6}' )
        if not cnt:
            print( f'{bucket_name:<30} -- no items' )
    def _disp_progress_put(self, bucket_name, object_id, n, eof=False):
        if n == 0:
            t = int( config['part_size'] / ( 1024*1024 ) )
            sys.stderr.write( f'send to {bucket_name}:{object_id}   part_size = {t}MB  max_put={config["max_put"]}\n')
        else:
            t = int( n / ( 1024*1024 ) )
            s = " EOF" if eof else ""
            sys.stderr.write( f'send to {bucket_name}:{object_id}   {t:>7} MB{s}\n')
    def _disp_progress_get(self, bucket_name, object_id, n, sz, eof=False):
        t1 = self.PrettyNum(n)
        t2 = self.PrettyNum(sz)
        s = " EOF" if eof else ""
        sys.stderr.write( f'get from {bucket_name}:{object_id}   {t1} of {t2}\n')
    def cmd_listall(self, parser):
        args = parser.parse_args()
        s3_cmd._disp_list_hdrs()
        buckets = ops['GetBuckets']()
        for bucket_name in buckets:
            self._disp_bucket(bucket_name)
    def cmd_list(self, parser):
        parser.add_argument('bucket_name')
        args = parser.parse_args()
        self._disp_list_hdrs()
        self._disp_bucket(args.bucket_name)
    def cmd_put(self, parser):

        parser.add_argument('bucket_name')
        parser.add_argument('object_id')
        args = parser.parse_args()

        id0 = f'{args.object_id}-s3_pipe'
        try:
            x,err = ops['GetObject'](args.bucket_name, id0)
            rr = json.loads(x)
            print( f'{args.bucket_name}:{id0} is already present.', file=sys.stderr)
            return
        except: pass

        src = sys.stdin.buffer
        o = mul_cmd()

        rr = { 'bucket_name': args.bucket_name,
               'object_id'  : args.object_id,
               'part_size'  : config['part_size'],
               'tot_size'   : 0,
               'part_cnt'   : 0,
               'parts'      : [] }

        if not args.quiet_opt: self._disp_progress_put(args.bucket_name, args.object_id, 0)

        while True:

            x = src.read(rr['part_size'])
            if len(x) <= 0:
                break

            rr['part_cnt'] += 1
            rr['tot_size'] += len(x)

            md  = hashlib.md5(x).digest()
            md5 = base64.b64encode(md).decode('utf-8')

            rr['parts'].append( { 'size': len(x),
                                  'md5' : md5 } )

            id = f'{args.object_id}-part{str(rr["part_cnt"]).zfill(8)}'

            if config['max_put'] <= 1:
                ops['PutObject'](args.bucket_name, id, x)
            else:
                o.put_obj(args.bucket_name, id, x)
                while o._job_cnt() > config["max_put"]:
                    time.sleep(0.5)

            eof = False if len(x) == rr['part_size'] else True
            if not args.quiet_opt: self._disp_progress_put(args.bucket_name, args.object_id, rr['tot_size'], eof=eof)

            if len(x) != rr['part_size']: break

        o._wait_for_jobs()

        x = json.dumps(rr, indent=4, sort_keys=True).encode('utf-8')
        id = f'{args.object_id}-s3_pipe'
        sum_rr = ops['PutObject'](args.bucket_name, id, x)
        if sum_rr:
            if 'Error' in sum_rr:
                print( json.dumps(rr, indent=4, sort_keys=True), file=sys.stderr)
                exit(1)

        if not args.quiet_opt:
            self.tm1 = int(time.time()*1000)
            rate = int( rr['tot_size'] / ( self.tm1 - self.tm0 ) * 1000 )
            print( f'{self.PrettyNum(rr["tot_size"])} saved in {self.PrettyTime(self.tm1-self.tm0)}  {self.PrettyNum(rate)}/sec', file=sys.stderr )
    def cmd_get(self, parser):
        parser.add_argument('bucket_name')
        parser.add_argument('object_id')

        args = parser.parse_args()

        id0 = f'{args.object_id}-s3_pipe'
        x,err = ops['GetObject'](args.bucket_name, id0)
        rr = json.loads(x)

        if not rr:
            sys.stderr.write( f'Cannot load {bucket_name}:{id0} control object.\n' )
            exit(1)

        dst = sys.stdout.buffer

        if not args.quiet_opt: self._disp_progress_get(args.bucket_name, args.object_id, 0, rr['tot_size'])

        n = 0
        part_no = 0
        for part_no in range(rr['part_cnt']):
            id = f'{args.object_id}-part{str(part_no+1).zfill(8)}'
            x,err = ops['GetObject'](args.bucket_name, id)
            md  = hashlib.md5(x).digest()
            md5 = base64.b64encode(md).decode('utf-8')
            md50 = rr['parts'][part_no]['md5']
            if md5 != rr['parts'][part_no]['md5']:
                sys.stderr.write( f'md5 error in part {part_no}  {md5} {md50}\n' )
                exit(1)

            dst.write(x)
            n += len(x)
            if not args.quiet_opt: self._disp_progress_get(args.bucket_name, args.object_id, n, rr['tot_size'])

        if not args.quiet_opt:
            self.tm1 = int(time.time()*1000)
            rate = int( rr['tot_size'] / ( self.tm1 - self.tm0 ) * 1000 )
            print( f'{self.PrettyNum(rr["tot_size"])} retrieved in {self.PrettyTime(self.tm1-self.tm0)}  {self.PrettyNum(rate)}/sec', file=sys.stderr )
    def cmd_delete(self, parser):
        parser.add_argument('bucket_name')
        parser.add_argument('object_id')
        args = parser.parse_args()

        id0 = f'{args.object_id}-s3_pipe'
        x = ""
        try:
            x,err = ops['GetObject'](args.bucket_name, id0)
            try:
                rr = json.loads(x)
            except:
                print('Error parsing {args.bucket_name}:{id} object.', file=sys.stderr)
                print(x, file=sys.stderr)
                exit(1)
        except:
            print('Error getting {args.bucket_name}:{id} object.', file=sys.stderr)
            print(x, file=sys.stderr)
            exit(1)

        if not rr:
            sys.stderr.write( f'Cannot load {bucket_name}:{id0} control object.\n' )
            exit(1)

        ids = []
        for n in range(rr['part_cnt']):
            ids.append( f'{args.object_id}-part{str(n+1).zfill(8)}' )
        ids.append( id0 )

        for id in ids:
            ops['DeleteObject'](args.bucket_name, id)

        print( f'{len(ids)} s3 objects have been deleted.' )
    def cmd_createbucket(self, parser):
        parser.add_argument('bucket_name')
        args = parser.parse_args()

        rr = ops['CreateBucket'](args.bucket_name)
        print(rr)
    def cmd_deletebucket(self, parser):
        parser.add_argument('bucket_name')
        args = parser.parse_args()

        ops['DeleteBucket'](args.bucket_name)

if __name__ == "__main__":
    if config['engine'] == 'boto3':
        s3_boto = s3_boto()
        ops = { 'GetBuckets'  : s3_boto.GetBuckets,
                'GetKeys'     : s3_boto.GetKeys,
                'CreateBucket': s3_boto.CreateBucket,
                'DeleteBucket': s3_boto.DeleteBucket,
                'GetObject'   : s3_boto.GetObject,
                'PutObject'   : s3_boto.PutObject,
                'DeleteObject': s3_boto.DeleteObject }
    elif config['engine'] == 'raw':
        s3_raw  = s3_raw()
        ops = { 'GetBuckets'  : s3_raw.GetBuckets,
                'GetKeys'     : s3_raw.GetKeys,
                'CreateBucket': s3_raw.CreateBucket,
                'DeleteBucket': s3_raw.DeleteBucket,
                'GetObject'   : s3_raw.GetObject,
                'PutObject'   : s3_raw.PutObject,
                'DeleteObject': s3_raw.DeleteObject }
    else: die()

    s3_cmd  = s3_cmd()
    cmds = { 'get'         : s3_cmd.cmd_get,
             'put'         : s3_cmd.cmd_put,
             'list'        : s3_cmd.cmd_list,
             'listall'     : s3_cmd.cmd_listall,
             'delete'      : s3_cmd.cmd_delete,
             'createbucket': s3_cmd.cmd_createbucket,
             'deletebucket': s3_cmd.cmd_deletebucket }

    cc = []
    for f in cmds:
        cc.append(f)

    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', choices=cc )
    parser.add_argument('-q', dest='quiet_opt', help='Quiet', action='store_true')
    try:
        args,x = parser.parse_known_args()
    except: exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', choices=[args.cmd])
    parser.add_argument('-q', dest='quiet_opt', help='Quiet', action='store_true')
    cmds[args.cmd](parser)

    exit(0)
