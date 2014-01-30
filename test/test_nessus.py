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
        io.BytesIO(data.encode('utf-8')), {'Content-Encoding': 'utf-8'}, '', status_code)

  @mock.patch.object(urllib.request, 'urlopen')
  def test_login(self, mock_urlopen):
    resp = {'reply': {'seq': '170692039', 'contents': {'plugin_set': '201401211115', 'scanner_boottime': '1391005598', 'user': {'name': 'admin', 'admin': 'TRUE', 'idx': '21232f297a57a5a743894a0e4a801fc3'}, 'server_uuid': '90936cf4-e94d-833c-c5d6-b50d941a2fb86bfbd6059081a72c', 'loaded_plugin_set': '201401211115', 'idle_timeout': '30', 'token': 'a1e627b2c1c03c9a220d5e7b4e502ab8b5b1e1f49d7d7844', 'msp': 'FALSE'}, 'status': 'OK'}}
    mock_urlopen.return_value = self._GetResp(json.dumps(resp))
    self._nessus.Login('test', 'pass')
    self.assertTrue(self._nessus.is_logged_in)

  @mock.patch.object(urllib.request, 'urlopen')
  def test_login_async(self, mock_urlopen):
    resp = {'reply': {'seq': '170692039', 'contents': {'plugin_set': '201401211115', 'scanner_boottime': '1391005598', 'user': {'name': 'admin', 'admin': 'TRUE', 'idx': '21232f297a57a5a743894a0e4a801fc3'}, 'server_uuid': '90936cf4-e94d-833c-c5d6-b50d941a2fb86bfbd6059081a72c', 'loaded_plugin_set': '201401211115', 'idle_timeout': '30', 'token': 'a1e627b2c1c03c9a220d5e7b4e502ab8b5b1e1f49d7d7844', 'msp': 'FALSE'}, 'status': 'OK'}}
    mock_urlopen.return_value = self._GetResp(json.dumps(resp))
    callback = mock.Mock(return_value=None)
    future = self._nessus.Login('test', 'pass', callback)
    futures.wait([future])
    self.assertTrue(self._nessus.is_logged_in)
    self.assertTrue(future.done())

  @mock.patch.object(urllib.request, 'urlopen')
  def test_with_logout(self, mock_urlopen):
    login_resp = {'reply': {'seq': '170692039', 'contents': {'plugin_set': '201401211115', 'scanner_boottime': '1391005598', 'user': {'name': 'admin', 'admin': 'TRUE', 'idx': '21232f297a57a5a743894a0e4a801fc3'}, 'server_uuid': '90936cf4-e94d-833c-c5d6-b50d941a2fb86bfbd6059081a72c', 'loaded_plugin_set': '201401211115', 'idle_timeout': '30', 'token': 'a1e627b2c1c03c9a220d5e7b4e502ab8b5b1e1f49d7d7844', 'msp': 'FALSE'}, 'status': 'OK'}}
    logout_resp = {'reply': {'seq': '170692039', 'status': 'OK'}}
    mock_urlopen.side_effect = [
        self._GetResp(json.dumps(login_resp)),
        self._GetResp(json.dumps(logout_resp))]
    with nessus.Nessus('host:port') as nes:
      nes.Login('user', 'pass')
    self.assertEquals(2, mock_urlopen.call_count)

if __name__ == "__main__":
  unittest.main()
