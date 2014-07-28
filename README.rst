========
pynessus
========

Client for the xml rpc interface of the Nessus vulnerability scanner v5+.

Methods mirror what is in the official API at
http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf
in a pythonic way so that you don't have to care about json or xml.

.. image:: https://travis-ci.org/attwad/pynessus.svg?branch=master
    :target: https://travis-ci.org/attwad/pynessus

Ongoing work
------------
Features are being added, not all the API is mapped yet.
As all the api calls kind of look the same, it is braindead work so pull
requests are more than welcome.

Example usage
-------------

.. code-block:: python

  with Nessus('127.0.0.1:8443') as nes:
    nes.Login('admin', 'pass$%&(#'%#[]@:')
    logging.info('Feeds: %s', nes.Feed())

All calls can also be done asynchronously if needed:

.. code-block:: python

  with Nessus('127.0.0.1:8443') as nes:
    def LoginCallback(result, error=None):
      if error:
        logging.warning('Error while logging: %s', error)
        return
      logging.info('Correcty logged in: %s', result)

    future = nes.Login('admin', 'pass$%&(#\'%#[]@:', callback=LoginCallback)
    futures.wait([future])
    # At this point the LoginCallback is sure to have been called.

License
-------

Unlicensed, do what you want. (http://unlicense.org/)
