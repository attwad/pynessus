from concurrent import futures
from unittest import mock
from urllib import response
import io
import json
import logging
import os
import unittest
import urllib

from pynessus import nessus

@mock.patch.object(urllib.request, 'urlopen')
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

  def test_login(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('login_ok')
    self._nessus.Login('test', 'pass')
    self.assertTrue(self._nessus.is_logged_in)

  def test_login_async(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('login_ok')
    callback = mock.Mock(return_value=None)
    future = self._nessus.Login('test', 'pass', callback)
    futures.wait([future])
    self.assertTrue(self._nessus.is_logged_in)
    self.assertTrue(future.done())

  def test_invalid_login(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('invalid_login')
    self.assertRaises(
        nessus.NessusError,
        self._nessus.Login, 'test', 'wrongpass')
    self.assertFalse(self._nessus.is_logged_in)

  def test_login_raises(self, mock_urlopen):
    mock_urlopen.side_effect = Exception('something went wrong')
    self.assertRaises(
        nessus.NessusError,
        self._nessus.Login, 'test', 'wrongpass')
    self.assertFalse(self._nessus.is_logged_in)

  def test_with_logout(self, mock_urlopen):
    mock_urlopen.side_effect = [
        self._ExpectResponseFromFile('login_ok'),
        self._ExpectResponseFromFile('logout_ok')]
    with nessus.Nessus('host:port') as nes:
      nes.Login('user', 'pass')
    self.assertEqual(2, mock_urlopen.call_count)

  def test_list_serversettings(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile(
        'server_securesettings_list_ok')
    settings = self._nessus.ListServerSettings()
    self.assertEqual({
        'proxysettings': {
            'custom_host': None,
            'proxy': None,
            'proxy_password': None,
            'proxy_port': None,
            'proxy_username': None,
            'user_agent': None
        }
    }, settings)

  def test_feed(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('feed_ok')
    feed = self._nessus.Feed()
    self.assertEqual({
        'diff': 'on',
        'expiration': '1548009584',
        'expiration_time': '1814',
        'feed': 'HomeFeed',
        'loaded_plugin_set': '201401211115',
        'msp': 'FALSE',
        'nessus_type': 'Nessus Home',
        'nessus_ui_version': '2.1.0',
        'plugin_rules': 'on',
        'report_email': 'on',
        'server_version': '5.2.5',
        'tags': 'on',
        'web_server_version': '5.0.0 (Build H20130829A)',
    }, feed)

  def test_list_server_preferences(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile(
        'server_preferences_ok')
    preferences = self._nessus.ListPreferences()
    self.assertEqual(41, len(preferences), preferences)

  def test_server_load(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('server_load_ok')
    load, platform = self._nessus.ServerLoad()
    self.assertEqual('WINDOWS', platform)
    self.assertEqual(5, len(load), load)

  def test_server_uid(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('server_uuid_ok')
    uuid = self._nessus.ServerUUID()
    self.assertEqual("90936cf4-e94d-833c-c5d6-b50d941a2fb86bfbd6059081a72c", uuid)

  def test_server_cert(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('server_cert')
    cert = self._nessus.ServerCert()
    self.assertTrue('CERTIFICATE' in cert, cert)

  def test_list_plugins(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile('list_plugins_ok')
    plugins = self._nessus.ListPlugins()
    self.assertEqual(47, len(plugins), plugins)

  def test_list_plugins_attributes(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile(
        'plugins_attributes_list')
    plugins = self._nessus.ListPluginsAttributes()
    self.assertEqual(37, len(plugins), plugins)

  def test_list_plugins_in_family(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile(
        'plugins_list_family_general')
    plugins = self._nessus.ListPluginsInFamily('General')
    self.assertEqual(164, len(plugins), plugins)

  def test_list_plugins_in_family_wrong_family(self, mock_urlopen):
    mock_urlopen.return_value = self._ExpectResponseFromFile(
        'plugins_list_family_null')
    plugins = self._nessus.ListPluginsInFamily('I am not a valid family')
    self.assertEqual([], plugins)


if __name__ == "__main__":
  logging.basicConfig(
      level=logging.ERROR,
      format='[%(levelname)s] (%(threadName)-10s) %(message)s',
  )
  unittest.main()
