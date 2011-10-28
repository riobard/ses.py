#!/usr/bin/env python
import hmac, urllib, httplib, sys
from hashlib import sha256
from base64 import b64encode
from datetime import datetime
from xml.dom import minidom
from getopt import gnu_getopt as getopt, GetoptError


class SESError(Exception):
    ''' Base error. All SES-related exceptions are dervied from this one. '''
    def __init__(self, msg=None, rsp=None):
        self.msg    = msg
        self.rsp    = rsp

    def __str__(self):
        return '{msg} | {status} {reason} {headers} {body}'.format(
                msg = self.msg, 
                status = self.rsp.status if self.rsp is not None else '',
                reason = self.rsp.reason if self.rsp is not None else '', 
                headers = self.rsp.msg if self.rsp is not None else '',
                body = self.rsp.body if self.rsp is not None else '')



## These are the exceptions that are most encountered. 
class SESThrottling(SESError): 
    ''' SES is throttling the sending process
    
    Usually this is due to exceeding max send rate or daily quota'''
    pass

class SESMaxSendRateExceeded(SESThrottling): 
    ''' Max send rate is exceeded. Slow down. '''
    pass

class SESDailyQuotaExceeded(SESThrottling):
    ''' Daily quota is exceeded. Stop sending until quota is replenished. '''
    pass


class SESMessageRejected(SESError): 
    ''' SES rejects the message for sending. 

    Read the error message to see why. 
    '''
    pass

class SESAddressBlacklisted(SESMessageRejected):
    ''' SES rejects the message for sending because the address is blacklisted. 

    An email address is blacklisted if SES received too many bounces or 
    complaints from the receipient's ISP. An email will stay in the blacklist
    for a while. Do not send to this address unless it gets delisted. 
    '''
    pass



def extract_xml(xml, keys, multiple=False):
    ''' Extract key-value dict from xml doc '''
    dom = minidom.parseString(xml)
    rs  = {}
    try:
        for key in keys:
            ls = dom.getElementsByTagName(key)
            if multiple:
                rs[key] = [e.childNodes[0].nodeValue for e in ls]
            else:
                rs[key] = ls[0].childNodes[0].nodeValue
        return rs
    
    except IndexError as e:
        raise SESError('Failed to extract keys {keys} from XML: {0}'.format(keys, xml))



def decode_error_response(xml):
    dom = minidom.parseString(xml)
    if len(dom.getElementsByTagName('ErrorResponse')) > 0:
        try:
            rs = extract_xml(xml, ['Type', 'Code', 'Message'])
            errtype = rs['Type']
            errcode = rs['Code']
            errmsg  = rs['Message']
            return errtype, errcode, errmsg
        except:
            return None
    else:
        return None



class SESConnection(object):
    '''
    A persistent connection to SES endpoint

        This is NOT THREAD-SAFE! We are reusing a single HTTPS connection to 
        do multiple request/reply cycles. 
    '''

    API_VERSION = '2010-12-01'
    API_XML_NAMESPACE = 'http://ses.amazonaws.com/doc/{date}/'.format(date=API_VERSION)
    API_ENDPOINT = 'email.us-east-1.amazonaws.com'  # just the host
    API_REQUEST_TIMEOUT = 15    # seconds

    def __init__(self, key_id, key, api_endpoint = None):
        self.key_id = key_id
        self.key    = key
        if api_endpoint is not None:
            self.API_ENDPOINT = api_endpoint

        # The persistent HTTPS connection object
        self.conn = httplib.HTTPSConnection(host=self.API_ENDPOINT,
                                            timeout=self.API_REQUEST_TIMEOUT)


    def api(self, body):
        ''' Call AWS SES service API '''
        # RFC2822 date format
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        signature = b64encode(hmac.new(self.key, date, sha256).digest())
        auth = 'AWS3-HTTPS AWSAccessKeyId={0},Algorithm={1},Signature={2}'.format(
                    self.key_id, 'HMACSHA256', signature)
        encoded_body = dict((k.encode('UTF-8') if isinstance(k, unicode) else k, 
                             v.encode('UTF-8') if isinstance(v, unicode) else v) 
                             for (k, v) in body.items())
        post_data = urllib.urlencode(encoded_body)  # urlencode does NOT take Unicode strings!
        headers = {'Date': date,
                   'X-Amzn-Authorization': auth,
                   'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                   'Content-Length': len(post_data),
                   'Connection': 'keep-alive'}

        try:
            self.conn.request('POST', '/', headers=headers, body=post_data)
            rsp = self.conn.getresponse()
            return self.process_response(rsp)
        except httplib.HTTPException as e:
            try: 
                raise SESError(str(e), rsp=rsp)
            except NameError:
                raise SESError(str(e))
        except IOError as e:
            try: 
                raise SESError(str(e), rsp=rsp)
            except NameError:
                raise SESError(str(e))


    def process_response(self, rsp):
        ''' Process respsonse from SES endpoint '''

        try:
            rsp.content_type = rsp.msg['content-type'].lower()
        except KeyError:
            rsp.content_type = ''

        try:
            rsp.content_length = int(rsp.msg['content-length'])
        except (ValueError, KeyError):
            rsp.content_length = -1

        rsp.body = rsp.read() if rsp.content_length > 0 else ''

        if rsp.content_type != 'text/xml':
            raise SESError('Response content-type is not text/xml', rsp=rsp)

        if len(rsp.body) != rsp.content_length:
            raise SESError('Incomplete response', rsp=rsp)

        if rsp.status == 200:
            return rsp.body
        else:
            rs = decode_error_response(rsp.body)
            if rs is not None:
                errtype, errcode, errmsg = rs
                msg = errmsg.lower()
                
                if errcode == 'MessageRejected':
                    if 'address' in msg and 'blacklisted' in msg:
                        raise SESAddressBlacklisted(errmsg, rsp=rsp)
                    else:
                        raise SESMessageRejected(errmsg, rsp=rsp)
                elif errcode == 'Throttling':
                    if 'rate' in msg:
                        raise SESMaxSendRateExceeded(errmsg, rsp=rsp)
                    elif 'quota' in msg:
                        raise SESDailyQuotaExceeded(errmsg, rsp=rsp)
                    else:
                        raise SESThrottling(errmsg, rsp=rsp)
                else:
                    raise SESError(errmsg, rsp=rsp)
            else:
                raise SESError('Unexpected response', rsp=rsp)


    @property
    def verified(self):
        ''' List verified email addresses '''
        xml = self.api({'Action': 'ListVerifiedEmailAddresses'})
        rs = extract_xml(xml, ['member'], True)['member']
        rs.sort()
        return rs


    def verify(self, addr):
        ''' Verify an email address
        
        SES will send a verification email to the address. The address will be verified
        after clicking a link in the verification email. 
        '''
        xml = self.api({'Action': 'VerifyEmailAddress', 'EmailAddress': addr})
        return extract_xml(xml, ['RequestId'])


    def delete(self, addr):
        ''' Delete a verified email address '''
        xml = self.api({'Action': 'DeleteVerifiedEmailAddress', 'EmailAddress': addr})
        return extract_xml(xml, ['RequestId'])


    @property
    def quota(self):
        ''' Get sending quota '''
        xml = self.api({'Action': 'GetSendQuota'})
        result = extract_xml(xml, [
            'Max24HourSend',    # max mails allowed to send in 24 hours
            'MaxSendRate',      # max mails allowed to send per second
            'SentLast24Hours'   # mails sent during the previous 24 hours
        ])

        d = {}
        for each in result:
            d[each] = int(float(result[each]))

        return d


    @property
    def stats(self):
        ''' Get sending statistics '''
        xml = self.api({'Action': 'GetSendStatistics'})
        rs  = extract_xml(xml, ['Timestamp', 'Bounces', 'Complaints', 
            'DeliveryAttempts', 'Rejects'], True)
        timestamps  = [datetime.strptime(e, '%Y-%m-%dT%H:%M:%SZ') 
                        for e in rs['Timestamp']]
        bounces     = [int(e) for e in rs['Bounces']]
        complaints  = [int(e) for e in rs['Complaints']]
        attempts    = [int(e) for e in rs['DeliveryAttempts']]
        rejects     = [int(e) for e in rs['Rejects']]
        ls = sorted(zip(timestamps, bounces, complaints, attempts, rejects))
        return [{'Timestamp': t, 'Bounces': b, 'Complaints': c, 'DeliveryAttempts': d,
                 'Rejects': r} for (t, b, c, d, r) in ls]


    def send(self, source, to = [], cc = [], bcc = [], reply_to = [], return_path = None,
             subject = None, html_body = None, text_body = None, charset = 'UTF-8'):
        ''' Send a structured email '''
        body = {'Action': 'SendEmail', 'Source': source}

        if subject:
            body['Message.Subject.Charset']     = charset
            body['Message.Subject.Data']        = subject.encode(charset) if isinstance(subject, unicode) else subject

        if text_body:
            body['Message.Body.Text.Charset']   = charset
            body['Message.Body.Text.Data']      = text_body.encode(charset) if isinstance(text_body, unicode) else text_body

        if html_body:
            body['Message.Body.Html.Charset']   = charset
            body['Message.Body.Html.Data']      = html_body.encode(charset) if isinstance(html_body, unicode) else html_body

        if return_path:
            body['ReturnPath'] = return_path

        # Fill in To, Cc, Bcc, and ReplyTo addresses
        for (t, addrs) in [('Destination.To',   to), 
                           ('Destination.Cc',   cc),
                           ('Destination.Bcc',  bcc),
                           ('ReplyTo',          reply_to)]:
            for (i, addr) in enumerate(addrs, 1):
                body['{0}Addresses.member.{1}'.format(t, i)] = addr

        xml = self.api(body)
        return extract_xml(xml, ['RequestId'])


    def send_raw(self, raw_mail):
        ''' Send a raw email. DKIM relies on this. '''
        raise NotImplementedError()

        body = {'Action': 'SendRawEmail'}
        xml  = self.api(body)
        return extract_xml(xml, ['RequstId', 'MessageId'])





def parse_credentials(filename):
    try:
        for line in open(filename).readlines():
            line = line.strip()
            if line.startswith('AWSAccessKeyId'):
                k, v    = line.split('=', 1)
                key_id  = v.strip()
            elif line.startswith('AWSSecretKey'):
                k, v    = line.split('=', 1)
                key     = v.strip()
        return key_id, key
    except IOError as e:
        if e.errno == 2:
            sys.exit('Credential file "{0}" not found. '.format(filename))
        else:
            raise




if __name__ == '__main__':

    USAGE = '''ses.py [action] -k [credentials file] [args]

Example
-------
1. Sending email:

    echo "email text body" | ses.py send -k [credentials file] -f from_addr -t [to_addr1,to_addr2,...] -c [cc_addr1,cc_addr2,...] -b [bcc_addr1,bcc_addr2,...] -s "email subject" 


2. Get send quota:

    ses.py quota -k [credentials file]


3. Get send statistics:

    ses.py stats -k [credentials file]


4. Get verified email addresses:

    ses.py verified -k [credentials file]


5. Verify email addreses:

    ses.py verify -k [credentials file] [addr1,addr2,...]


6. Delete verified email addresses:

    ses.py delete -k [credentials file] [addr1,addr2,...]


Credentials file example
------------------------

    AWSAccessKeyId=XXXXXXXXXXXXXXXXXXXX
    AWSSecretKey=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
'''


    def parse_opts(cmd_opts):
        try:
            opts, args = getopt(cmd_opts, 'k:a:hs:f:t:c:b:', ['help'])
            return dict(opts), args
        except GetoptError as e:
            sys.exit(e)


    def get_action(args):
        if len(args) > 0:
            return args[0].lower()
        else:
            sys.exit('Action required. ')

    def get_credentials(opts):
        if '-k' in opts:
            key_id, key = parse_credentials(opts['-k'])
            return key_id, key
        else:
            sys.exit('Credentials file "-k" required. ')


    class Actions():
        ' Action container ' 

        @staticmethod
        def quota(ses, opts, args):
            for (k, v) in ses.quota.items():
                print '{0:20}{1}'.format(k, v)


        @staticmethod
        def stats(ses, opts, args):
            for d in ses.stats:
                print ' '.join(['{t}',
                                'Bounces={b}',
                                'Complaints={c}', 
                                'DeliveryAttempts={d}',
                                'Rejects={r} ']).format(
                                    t=d['Timestamp'],
                                    b=d['Bounces'],
                                    c=d['Complaints'],
                                    d=d['DeliveryAttempts'],
                                    r=d['Rejects'])


        @staticmethod
        def verified(ses, opts, args):
            for each in ses.verified:
                print each


        @staticmethod
        def verify(ses, opts, args):
            addrs = [e for e in args[1].split(',') if e!= '']
            for each in addrs:
                ses.verify(each)
                print 'Verification email sent to {0}'.format(each)


        @staticmethod
        def delete(ses, opts, args):
            addrs = [e for e in args[1].split(',') if e!= '']
            for each in addrs:
                ses.delete(each)
                print 'Deleted verified email address {0}'.format(each)


        @staticmethod
        def send(ses, opts, args):
            if '-f' in opts:
                source  = opts.get('-f')
            else:
                sys.exit('Mail source "-f" required')

            subject = opts.get('-s', None)
            to      = [e for e in opts.get('-t', '').split(',') if e != '']
            bcc     = [e for e in opts.get('-b', '').split(',') if e != '']
            cc      = [e for e in opts.get('-c', '').split(',') if e != '']
            body    = sys.stdin.read()
            ses.send(source=source, subject=subject, to=to, cc=cc, bcc=bcc, 
                     text_body=body)



    def main():
        opts, args = parse_opts(sys.argv[1:])
        if '-h' in opts or '--help' in opts:
            sys.exit(USAGE)

        action = get_action(args)
        if not hasattr(Actions, action):
            sys.exit('Unknown action: {0}'.format(action))

        try:
            key_id, key = get_credentials(opts)
            sesconn = SESConnection(key_id, key)
            getattr(Actions, action)(sesconn, opts, args)
        except SESError as e:
            sys.exit('Error: {0}'.format(e))
    
    main()
