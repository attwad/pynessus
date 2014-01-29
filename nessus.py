from concurrent import futures
from urllib import request
import collections
import functools
import json
import logging
import random
import sys
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
    self._executor = futures.ThreadPoolExecutor(max_workers=1)

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
      future.add_done_callback(functools.partial(self._SimpleReturnCB, callback))
      return future
    else:
      futures.wait([future])
      self._SimpleReturnCB(callback, future)

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


if __name__ == '__main__':
  nessus = Nessus()
  def callback(status):
    logging.info('Future finished: %s', status)
  nessus.Login('admin', 'simplerpass')
  logging.info('Feed: %s', nessus.Feed())
  nessus.ListServerSettings()
  nessus.Logout()
