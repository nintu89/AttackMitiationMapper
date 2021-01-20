import re
import requests
from bs4 import BeautifulSoup

from stix2 import TAXIICollectionSource
from stix2 import Filter
from taxii2client.v20 import Server
from taxii2client.v20 import Collection

# globals
TAXII_SERVER = "https://cti-taxii.mitre.org/taxii/"
SUCCESS = (200,)


def execute(method, url, payload=None,
            user=None, password=None):
    """
    Execute rest api
    :param method:  http method
    :param url: rest endpoint
    :param payload: body of request
    :param user:
    :param passowrd:
    :return:
    """
    headers = {'Content-Type': "text/html; charset=utf-8"}
    response = requests.request(
        method=method,
        url=url,
        auth=None,
        headers=headers,
        data=payload,
        verify=True
    )
    if response.status_code not in SUCCESS:
        raise RuntimeError(
            "Failed\n",
            "================\n"
            "url: [%s]\n"
            "status_code: [%s]\n"
            "reason: [%s]\n"
            % (url, response.status_code, response.reason)
        )
    return response


def get_mitigations_from_html(html_body):
    """
    extract mitigations from html code
    :param html_body: html content
    :return:
    """

    def extract_migration_ids(data):
        match = re.search('\/mitigations\/(M\d+)', str(data))
        try:
            return match.groups()[0]
        except IndexError:
            raise IndexError("Unable to find mitigation id from html data")

    soup = BeautifulSoup(html_body, 'html5lib')
    raw_data = soup.find_all(href=re.compile('mitigations/M\d+'))
    mitigations = list(map(extract_migration_ids, raw_data))
    return mitigations


def get_collection_url_by_type(collections, atype="Enterprise"):
    """
    Get the collection url for given collection type
    :param collections: list of collection objects
    :param atype: type of collection Enterprise, Mobile etc
    :return: url
    """
    return [x.url for x in collections if atype in x._title][0]


def get_attack_url_by_id(ext_id):
    """
    Get the attack url for given attack id
    :param ext_id: id of attack-pattern e.g. T1504
    :return: url
    """
    attack_sdo = get_attack_by_id(ext_id)
    return attack_sdo.external_references[0].url


def display_mitigation_by_ids(ext_id):
    """
    Get the mitigation sdo using given id
    :param ext_id: id of mitigation e.g M1047
    :return: mitigation sdo
    """
    sdo = get_mitigation_by_id(ext_id)
    print("========================")
    print(sdo.name)
    print("========================")
    print(sdo)


def get_attack_by_id(ext_id):
    """
    Get attack sdo for given id
    :param ext_id: id of attack-pattern e.g T1504
    :return: attack-pattern sdo
    """
    src = get_collection_src()
    sdo_list = src.query([Filter("external_references.external_id", "=", ext_id),
                          Filter("type", "=", "attack-pattern")])
    if sdo_list:
        return sdo_list[0]
    else:
        raise RuntimeError("Unable to get any attack-pattern sdo with id [%s]" % ext_id)


def get_mitigation_by_id(ext_id):
    """
    Get attack sdo for given id
    :param ext_id: id of attack-pattern e.g T1504
    :return: attack-pattern sdo
    """
    src = get_collection_src()
    sdo_list = src.query([Filter("external_references.external_id", "=", ext_id),
                          Filter("type", "=", "course-of-action")])
    if sdo_list:
        return sdo_list[0]
    else:
        raise RuntimeError("Unable to get any course-of-action sdo with id [%s]" % ext_id)


def get_collection_src():
    """
    Get collection src from collections objects provided by TAXII_SERVER
    :return: collection source object
    """
    server = Server(TAXII_SERVER)

    collections = server.api_roots[0].collections
    collection_url = get_collection_url_by_type(collections, atype="Enterprise")
    src = TAXIICollectionSource(Collection(collection_url))
    return src
