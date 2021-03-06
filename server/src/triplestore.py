'''
Uploads annotation RDF files to a triplestore.

Author:     Keith M Lawrence    <keith@kludge.co.uk>
Version:    2014-06-28
'''

from os.path import join as path_join
from os import environ
from session import get_session

import requests

from document import real_directory
from message import Messager
from rdfIO import convert_to_rdf
from rdfIO import load_namespace_info

def upload_annotation(document, collection):
    '''Uploads an annotation into a triplestore.

    The triplestore endpoint path is specified by environment - it can be
    set in apache with the SetEnv directive, either in a local .htaccess
    file or in the main configuration for the brat directory. It assumes
    that the triplestore implements the 1.1 RESTFUL interface, as for
    example 4Store and Sesame are supposed to, whereby you can PUT to the
    graph to replace it. This function is called from the dispatcher when
    an AJAX 'uploadAnnotation' call comes in.
    '''
    directory = collection
    real_dir = real_directory(directory)
    fname = '%s.%s' % (document, 'ann')
    fpath = path_join(real_dir, fname)
    user = get_session()['user']

    # Get target sparql endpoint from the environment

    if 'TRIPLESTORE_RESTFUL_ENDPOINT' not in environ:
        Messager.error('No Triplestore endpoint set! ' +
            '(Must be set in Apache with SetEnv ' +
            'TRIPLESTORE_RESTFUL_ENDPOINT <url>)')
        return

    namespace_info = load_namespace_info()
    
    endpoint = environ['TRIPLESTORE_RESTFUL_ENDPOINT'] + \
        namespace_info['base_url'] + 'user/' + user + '/' + document

    rdf_data = convert_to_rdf(fpath, document)
    headers = {'content-type' : 'application/x-turtle'}

    response = requests.put(endpoint, headers=headers, data=rdf_data)

    if response.status_code == 201 or response.status_code == 200:
        Messager.info('Uploaded data to triplestore')
    else:
        Messager.error('Failed to upload to triplestore (Response ' +
            str(response.status_code) + ' ' + response.reason + ')')

    return {}

