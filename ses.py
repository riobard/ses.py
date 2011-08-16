import hashlib
import hmac
import datetime
import base64
import urllib
import urllib2
import time, calendar
from xml.parsers.expat import ParserCreate
from xml.dom import minidom


def extract_xml(xml, keys):
    ''' Extract key-value dict from xml doc '''

    print 'CALLING extract_xml'

    state   = {'current_node': None}
    result  = {}
    
    def start_element(name, attrs):
        if name in set(keys):
            state['current_node'] = name

    def end_element(name):
        if state['current_node'] == name:
            state['current_node'] = None

    def char_data(data):
        if state['current_node'] in set(keys):
            result[state['current_node']] = data

    parser = ParserCreate()
    parser.StartElementHandler  = start_element
    parser.EndElementHandler    = end_element
    parser.CharacterDataHandler = char_data
    parser.Parse(xml)

    return result


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


class SESException(Exception):
    def __init__(self, Type='', Code='', Message='', RequestId=''):
        self.type = Type
        self.code = Code
        self.msg  = Message
        self.reqid= RequestId

    def __str__(self):
        return ('[ErrorResponse] {msg}|{type}|{code}|{reqid}').format(
                type=self.type, code=self.code, msg=self.msg, reqid=self.reqid)


class SESError(Exception):
    pass


class SES(object):

    SES_URL = 'https://email.us-east-1.amazonaws.com/'
    REQUEST_TIMEOUT = 30

    def __init__(self, key_id, key):
        self.key_id = key_id
        self.key    = key



    def parse_error_response(self, xml):
        keys = ['Type', 'Code', 'Message', 'RequestId']
        return extract_xml(xml, keys)


    def api(self, body):
        ''' Call AWS SES service '''

        # RFC2822 date format
        date = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        signature = base64.b64encode(hmac.new(self.key, date, hashlib.sha256).digest())
        auth = 'AWS3-HTTPS AWSAccessKeyId={kid},Algorithm={algo},Signature={sig}'.format(
                    kid=self.key_id, algo='HMACSHA256', sig=signature)
        post_data = urllib.urlencode(body)
        headers = {'Date': date,
                   'X-Amzn-Authorization': auth,
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': len(post_data)}
        try: 
            req = urllib2.Request(self.SES_URL, post_data, headers)
            rsp = urllib2.urlopen(req, timeout=self.REQUEST_TIMEOUT)
            if 100 <= rsp.code < 300:   # success
                return ''.join(rsp.readlines())

        except urllib2.HTTPError as e:
            if 400 <= e.code < 500:
                xml = ''.join(e.readlines())
                error = self.parse_error_response(xml)
                raise SESException(**error)

        except urllib2.URLError as e:
            raise SESError(e)


    @property
    def verified_addr(self):
        xml = self.api({'Action': 'ListVerifiedEmailAddresses'})
        dom = minidom.parseString(xml)
        members = dom.getElementsByTagName('member')
        rs  = [e.childNodes[0].nodeValue for e in members]
        rs.sort()
        return rs


    def verify_addr(self, addr):
        xml = self.api({'Action'       : 'VerifyEmailAddress',
                        'EmailAddress' : addr})
        return extract_xml(xml, ['RequestId'])


    def del_verified_addr(self, addr):
        xml = self.api({'Action'       : 'DeleteVerifiedEmailAddress',
                        'EmailAddress' : addr})
        return extract_xml(xml, ['RequestId'])


    @property
    def quota(self):
        xml = self.api({'Action': 'GetSendQuota'})
        result = extract_xml(xml, [
            'Max24HourSend',    # max mails allowed to send in 24 hours
            'MaxSendRate',      # max mails allowed to send per second
            'SentLast24Hours'   # mails sent during the previous 24 hours
        ])

        d = {}
        for each in result:
            d[str(each)] = int(float(result[each]))

        return d


    @property
    def stats(self):
        xml = self.api({'Action': 'GetSendStatistics'})
        dom = minidom.parseString(xml)

        timestamps = [calendar.timegm(time.strptime(
            e.childNodes[0].nodeValue, '%Y-%m-%dT%H:%M:%SZ')) for e in 
            dom.getElementsByTagName('Timestamp')]

        bounces = [int(e.childNodes[0].nodeValue) for e in 
                dom.getElementsByTagName('Bounces')]

        complaints = [int(e.childNodes[0].nodeValue) for e in 
                dom.getElementsByTagName('Complaints')]

        delivery_attempts =  [int(e.childNodes[0].nodeValue) for e in 
                dom.getElementsByTagName('DeliveryAttempts')]

        rejects = [int(e.childNodes[0].nodeValue) for e in 
                dom.getElementsByTagName('Rejects')]

        rs = sorted(zip(timestamps, bounces, complaints, delivery_attempts, rejects))
        return [{'Timestamp': t, 'Bounces': b, 'Complaints': c, 'DeliveryAttempts': d,
                 'Rejects': r} for (t, b, c, d, r) in rs]


    def send(self, mail):
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

        return self.api(body)


    def send_raw(self, raw_mail):
        # DKIM replies on raw emails
        raise NotImplementedError()

        body = {'Action': 'SendRawEmail'}
        xml  = self.api(body)
        return extract_xml(xml, ['RequstId', 'MessageId'])


