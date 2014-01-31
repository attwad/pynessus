"""Library to talk with a remote Nessus 5 server that via its xmlrpc interface,

Methods mirror what is in the official API at
file:///C:/Users/Tmu/Desktop/nessus/nessus_5.0_XMLRPC_protocol_guide.pdf

Example usage:
  nessus = Nessus('127.0.0.1:8443')
  nessus.Login('admin', 'pass$%&(#'%#[]@:')
  logging.info('Feeds: %s', nessus.Feed())
  nessus.Logout()
"""

from concurrent import futures
from urllib import request
import functools
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
  """Class to communicate with the remote nessus 5 instance.
  All methods support both synchronous and asynchronous calls.
  """

  def __init__(self, host, executor=None):
    self._host = host
    self._session_token = None
    self._executor = executor or futures.ThreadPoolExecutor(max_workers=5)

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    if self._session_token:
      self.Logout()

  def _BuildRequest(self, path, data=None):
    request = urllib.request.Request(HOST + path + '?json=1')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8')
    request.add_header('Accept', 'application/json')
    if data:
      data = urllib.parse.urlencode(data)
      data = data.encode('utf-8')
      request.data = data
    if self._session_token:
      # TODO: dangerous.
      request.add_header('Cookie', 'token=%s' % self._session_token)
    return request

  @staticmethod
  def _SendRequest(request):
    logging.debug('Sending request to %s with data %s',
        request.get_full_url(), request.data)
    resp = urllib.request.urlopen(request)
    url_info = resp.info()
    encoding = url_info.get('Content-Encoding', 'utf-8')
    raw_json = resp.read().decode(encoding)
    logging.debug('urlopen returned \n%s\n', raw_json)
    json_resp = json.loads(raw_json)['reply']
    status = json_resp.get('status', '')
    if status != 'OK':
      raise NessusError('Status was not OK: %s' % status)
    return json_resp['contents']

  def Login(self, login, password, callback=None):
    data = {
      'login': login,
      'password': password,
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/login', data)
    future = self._executor.submit(self._SendRequest, request)
    if callback:
      future.add_done_callback(functools.partial(self._LoginDone, callback))
      return future
    else:
      futures.wait([future])
      self._LoginDone(callback, future)

  def _LoginDone(self, callback, future):
    contents = future.result()
    self._session_token = contents['token']
    logging.debug('Token is %s', self._session_token)
    if callback:
      callback('Successully connected to Nessus')

  def _SimpleReturnCB(self, callback, future):
    if callback:
      callback(future.result())
    else:
      return future.result()

  def Logout(self, callback=None):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/logout', data)
    future = self._executor.submit(self._SendRequest, request)
    if callback:
      future.add_done_callback(functools.partial(self._LogoutDone, callback))
      return future
    else:
      futures.wait([future])
      self._LogoutDone(callback, future)

  def _LogoutDone(self, callback, future):
    self._session_token = None
    logging.debug('Token is %s', self._session_token)
    if callback:
      callback('Successully connected to Nessus')
    
  @property
  def is_logged_in(self):
    return self._session_token is not None

  def Feed(self, callback=None):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/feed', data)
    future = self._executor.submit(self._SendRequest, request)
    if callback:
      future.add_done_callback(functools.partial(self._SimpleReturnCB, callback))
      return future
    else:
      futures.wait([future])
      return self._SimpleReturnCB(callback, future)

  def ListServerSettings(self, callback=None):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/server/securesettings/list', data)
    future = self._executor.submit(self._SendRequest, request)
    if callback:
      future.add_done_callback(
          functools.partial(self._ListServerSettingsDone, callback))
      return future
    else:
      futures.wait([future])
      return self._ListServerSettingsDone(callback, future)

  def _ListServerSettingsDone(self, callback, future):
    contents = future.result()
    settings = contents.get('securesettings')
    if callback:
      callback(settings)
    else:
      return settings

  def PluginsDescriptions(self, callback=None):
    data = {
      'seq': random.randint(1, MAX_SEQ),
    }
    request = self._BuildRequest('/plugins/descriptions', data)
    future = self._executor.submit(self._SendRequest, request)
    if callback:
      future.add_done_callback(
          functools.partial(self._SimpleReturnCB, callback))
      return future
    else:
      futures.wait([future])
      return self._SimpleReturnCB(callback, future)


if __name__ == '__main__':
  def callback(status):
    logging.info('Future finished: %s', status)
  with Nessus(HOST) as nessus:
    nessus.Login('admin', 'simplerpass')
    logging.info('Feed: %s', nessus.Feed())
    logging.info('Server settings: %s', nessus.ListServerSettings())
    # plugins = nessus.PluginsDescriptions()
