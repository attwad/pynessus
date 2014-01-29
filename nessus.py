from urllib import request
import collections
import json
import logging
import random
import urllib

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] (%(threadName)-10s) %(message)s',
)

HOST = 'https://127.0.0.1:8443'
MAX_SEQ = 2 ** 31 - 1


class NessusError(Exception):
  pass


class Nessus(object):

  def __init__(self):
    self._session_token = None

  def _BuildRequest(self, path, data=None):
    request = urllib.request.Request(HOST + path + '?json=1')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8')
    request.add_header('Accept', 'application/json')
    if data:
      data = urllib.parse.urlencode(data)
      data = data.encode('utf-8')
      request.add_data(data)
    if self._session_token:
      # TODO: dangerous.
      request.add_header('Cookie', 'token=%s' % self._session_token)
    return request

  @staticmethod
  def _SendRequest(request):
    logging.debug('Sending request to %s with data %s',
        request.get_full_url(), request.get_data())
    resp = urllib.request.urlopen(request)
    url_info = resp.info()
    encoding = url_info.get('Content-Encoding', 'utf-8')
    json_resp = json.loads(resp.read().decode(encoding))['reply']
    logging.debug('urlopen returned %s', json_resp)
    status = json_resp.get('status', '')
    if status != 'OK':
      raise NessusError('Status was not OK: %s' % status)
    return json_resp['contents']

  def Login(self, login, password):
    data = {
      'login': login,
      'password': password,
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/login', data)
    contents = self._SendRequest(request)

    self._session_token = contents['token']
    logging.debug('Token is %s', self._session_token)

  def Logout(self):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/logout', data)
    contents = self._SendRequest(request)
    return contents

  def Feed(self):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/feed', data)
    contents = self._SendRequest(request)
    return contents

  def ListServerSettings(self):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/server/securesettings/list', data)
    contents = self._SendRequest(request)
    return contents.get('securesettings')


if __name__ == '__main__':
  nessus = Nessus()
  nessus.Login('admin', 'simplerpass')
  # logging.info('Feed info: %s', nessus.Feed())
  # logging.info('Server settings list: %s', nessus.ListServerSettings())
  logging.info('Logout: %s', nessus.Logout())
