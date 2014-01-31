import os
from unittest import mock
import unittest
import urllib
import io
from urllib import response
import json
from concurrent import futures

from pynessus import nessus

class TestNessus(unittest.TestCase):

  def setUp(self):
    self._nessus = nessus.Nessus('hostname:port')

  @staticmethod
  def _GetResp(data, status_code=200):
    return response.addinfourl(
        io.BytesIO(data.encode('utf-8')),
        {'Content-Encoding': 'utf-8'},
        '',
        status_code)

  @staticmethod
  def _ExpectResponseFromFile(filename, status_code=200):
    with open(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'testdata',
        filename + '.json')) as f:
       return response.addinfourl(
          io.BytesIO(f.read().encode('utf-8')),
          {'Content-Encoding': 'utf-8'},
          '',
          status_code)

  @mock.patch.object(urllib.request, 'urlopen')
  def test_login(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('login_ok')
    self._nessus.Login('test', 'pass')
    self.assertTrue(self._nessus.is_logged_in)

  @mock.patch.object(urllib.request, 'urlopen')
  def test_login_async(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('login_ok')
    callback = mock.Mock(return_value=None)
    future = self._nessus.Login('test', 'pass', callback)
    futures.wait([future])
    self.assertTrue(self._nessus.is_logged_in)
    self.assertTrue(future.done())

  @mock.patch.object(urllib.request, 'urlopen')
  def test_with_logout(self, mock_urlopen):
    logout_resp = {'reply': {'seq': '170692039', 'status': 'OK'}}
    mock_urlopen.side_effect = [
        self._ExpectResponseFromFile('login_ok'),
        self._ExpectResponseFromFile('logout_ok')]
    with nessus.Nessus('host:port') as nes:
      nes.Login('user', 'pass')
    self.assertEquals(2, mock_urlopen.call_count)


if __name__ == "__main__":
  unittest.main()
