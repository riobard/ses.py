#!/usr/bin/python
import hmac
from hashlib import sha256
from base64 import b64encode
import urllib
import urllib2
from datetime import datetime
from xml.dom import minidom


class SESError(Exception):
    def __init__(self, msg=None, **kargs):
        self.msg    = msg
        self.kargs  = kargs

    def __str__(self):
        s = [] if self.msg is None else [self.msg]
        for (k, v) in self.kargs.items():
            s.append('{0}={1}'.format(k, v))
        rs = '|'.join(s)
        return rs


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
        raise SESError('Failed to extract values from XML: {0}'.format(xml))


class SESMail(object):
    def __init__(self, source, to, cc=[], bcc=[], reply_to = [],
            subject=None, text_body=None, html_body=None, charset='UTF-8'):

        self.source     = source
        self.to         = to
        self.cc         = cc
        self.bcc        = bcc
        self.reply_to   = reply_to
        self.subject    = subject
        self.html_body  = html_body
        self.text_body  = text_body
        self.charset    = charset


class SES(object):

    API_VERSION = '2010-12-01'
    API_URL = 'https://email.us-east-1.amazonaws.com/'
    API_REQUEST_TIMEOUT = 30    # seconds

    def __init__(self, key_id, key):
        self.key_id = key_id
        self.key    = key


    def api(self, body):
        ''' Call AWS SES service API '''
        # RFC2822 date format
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        signature = b64encode(hmac.new(self.key, date, sha256).digest())
        auth = 'AWS3-HTTPS AWSAccessKeyId={0},Algorithm={1},Signature={2}'.format(
                    self.key_id, 'HMACSHA256', signature)
        post_data = urllib.urlencode(body)
        headers = {'Date': date,
                   'X-Amzn-Authorization': auth,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': len(post_data)}
        try: 
            req = urllib2.Request(self.API_URL, post_data, headers)
            rsp = urllib2.urlopen(req, timeout=self.API_REQUEST_TIMEOUT)
            if 100 <= rsp.code < 300:   # success
                res = ''.join(rsp.readlines())
                if res is None:
                    raise SESError('Error SES response: {0}'.format(str(rsp)))
                else:
                    return res
            else:
                raise SESError('HTTP request error: {0}'.format(str(rsp)))

        except urllib2.HTTPError as e:
            if 400 <= e.code < 500:
                xml = ''.join(e.readlines())
                error = extract_xml(xml, ['Type', 'Code', 'Message', 'RequestId'])
                raise SESError(**error)

        except urllib2.URLError as e:
            raise SESError(str(e))


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


    def send(self, mail):
        ''' Send a structured email '''
        body = {'Action': 'SendEmail', 'Source': mail.source}

        if mail.subject is not None:
            body['Message.Subject.Charset']     = mail.charset
            body['Message.Subject.Data']        = mail.subject

        if mail.text_body is not None:
            body['Message.Body.Text.Data']      = mail.text_body
            body['Message.Body.Text.Charset']   = mail.charset

        if mail.html_body is not None:
            body['Message.Body.Html.Data']      = mail.html_body
            body['Message.Body.Html.Charset']   = mail.charset

        # Fill in To, Cc, Bcc, and ReplyTo addresses
        for (t, addrs) in [('Destination.To',   mail.to), 
                           ('Destination.Cc',   mail.cc),
                           ('Destination.Bcc',  mail.bcc),
                           ('ReplyTo',          mail.reply_to)]:
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
    import sys
    from getopt import gnu_getopt as getopt, GetoptError

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
                                '{b} Bounces',
                                '{c} Complaints', 
                                '{d} DeliveryAttempts',
                                '{r} Rejects']).format(
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
            mail = SESMail(source=source, subject=subject, to=to, cc=cc, bcc=bcc, 
                        text_body=body)
            ses.send(mail)



    def main():
        opts, args = parse_opts(sys.argv[1:])
        if '-h' in opts or '--help' in opts:
            sys.exit(USAGE)

        action = get_action(args)
        if not hasattr(Actions, action):
            sys.exit('Unknown action: {0}'.format(action))

        try:
            key_id, key = get_credentials(opts)
            ses         = SES(key_id, key)
            getattr(Actions, action)(ses, opts, args)
        except SESError as e:
            sys.exit('Error: {0}'.format(e))
    
    main()
