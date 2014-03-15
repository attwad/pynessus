========
pynessus
========

Client for the xml rpc interface of the Nessus vulnerability scanner v5+.

Methods mirror what is in the official API at
http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf

Ongoing work
------------
Features are being added, not all the API is mapped yet.
It is braindead work so pull requests are welcome of course.
When the library has reached a stable state I will release the package in pypi.

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
