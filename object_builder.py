__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import simplejson as json
import urllib
import urllib2
import os
import time
import pdfparser
import pdfid_mod
import related_entropy
import hashlib
import hash_maker
import argparse
import logging
import sys

DEFAULTDUMPFILE = "malpdfobj_out.json"

VIRUSTOTAL_API_KEY = "YOUR_VT_KEY"
PDF_ELEMENT_INDIRECT_OBJECT = 2

def main():
    oParser = argparse.ArgumentParser(description=__description__)
    oParser.add_argument('malpdf', metavar="PDFfile",
                         help='PDF file to build an object from')
    oParser.add_argument('-f', "--file",
                         help='file to dump results in JSON format')
    # oParser.add_option('-d', '--dir', default='',
    #                   type='string', help='dir to build an object from')
    oParser.add_argument(
        '-m', '--mongo', action='store_true', default=False,
        help='dump to a mongodb database')
    oParser.add_argument(
        '-v', '--verbose', action='store_true', default=False,
        help='verbose log output')
    oParser.add_argument(
        '-x', '--exhaustive', action='store_true', default=False,
        help='exhaustive output of the tool')
    oParser.add_argument(
        '-l', '--log', action="store_true",
        help='log to provided file')
    oParser.add_argument(
        '-X', '--hexa', action='store_true', default=False,
        help='Provide also streams in hexadecimal representations')
    oParser.add_argument(
        '-V', '--virustotal', action='store_true', default=False,
        help='Use VirusTotal API to get info from provided pdf')
    oParser.add_argument(
        '-H', '--hashes', action='store_true', default=False,
        help='Computes hashes for provided file')
    oParser.add_argument(
        '-W', '--wepawet', action='store_true', default=False,
        help='Not implemented.')
    options = oParser.parse_args()

    dumpfile = options.file if options.file is not None else DEFAULTDUMPFILE

    global log
    log = logging.getLogger("malpdfobj")
    if options.log:
        h = logging.FileHandler(options.log, mode='w')
    else:
        h = logging.StreamHandler()

    if options.verbose:
        log.setLevel(logging.DEBUG)
        h.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        h.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    h.setFormatter(formatter)
    log.addHandler(h)

    if options.mongo:
        try:
            import pymongo
            from pymongo import Connection
        except:
            log.error("Install mongodb before to use it. Exit.")
            sys.exit()
        con = connect_to_mongo("localhost", 27017, "pdfs", "malware")

    malpdf = os.path.abspath(options.malpdf)

    output = build_obj(malpdf, vt=options.virustotal,
                       wepawet=options.wepawet, hashes=options.hashes,
                       exhaustive=options.exhaustive, hexa=options.hexa)
    if options.mongo:
        con.insert(output)
    elif options.file:
        dump_fh = open(dumpfile, 'w')
        dump_fh.write(json.dumps(output))
        dump_fh.close()
    else:
        print(output)


def get_vt_obj(file):
    if VIRUSTOTAL_API_KEY == "YOUR_VT_KEY":
        log.error("Setup your VirusToal API key at the beginning of the script")
        return {}
    url = "https://www.virustotal.com/api/get_file_report.json"
    parameters = {"resource": file, "key": VIRUSTOTAL_API_KEY}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    log.debug("VirusTotal requesting...")
    response = urllib2.urlopen(req)
    vtobj = response.read()

    preprocess = json.loads(vtobj)
    report = preprocess.get("report")
    permalink = preprocess.get("permalink")
    result = preprocess.get("result")

    if int(result) == 1:
        scanners = []
        last_scan = report[0]
        for k, v in report[1].iteritems():
            scanner = {'antivirus': k, 'signature': v}
            scanners.append(scanner)

        vtobj = {'report': {'last_scan': last_scan, 'permalink':
                            permalink, 'results': {'scanners': scanners}}}
    else:
        log.error("VirusTotal requests did not give results")
        vtobj = {'report': {'results': {'scanners': []}}}

    return vtobj


def get_wepawet_obj():
    # submission script exist on wepawet website, but getting result need web
    # scrapping
    log.error("Wepawet is not implemented")
    return "null"


def get_structure(file, exhaustive):
    structureobj = pdfid_mod.PDFiD2JSON(
        pdfid_mod.PDFiD(file, exhaustive, exhaustive, False, True))
    return structureobj


def get_scores(file):
    scoreobj = pdfid_mod.Score2JSON(
        pdfid_mod.PDFiD(file, False, True, False, True))
    return scoreobj


def get_hash_obj(file):
    hashes = hash_maker.get_hash_object(file)
    return {'file': hashes}


def get_contents_obj(file, hexa):
    return {'objects': get_contents(file, hexa)}

def get_contents(file, hexa):
    oPDFParser = pdfparser.cPDFParser(file)
    content_json_objs = []

    while True:
        object = oPDFParser.GetObject()
        if object != None:
            if object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                content_json_objs.append(pdfparser.content2JSON(object, hexa))
        else:
            break

    return {'object': content_json_objs}


def get_related_files(file):
    return related_entropy.shot_caller(file)


def connect_to_mongo(host, port, database, collection):
    connection = Connection(host, port)
    db = connection[database]
    collection = db[collection]
    return collection


def kill_database_connection(conn):  # 9b+
    conn.commit()
    conn.close()


def build_obj(malpdf, vt=False, wepawet=False, hashes=False, exhaustive=False,
              hexa=False):

    # get the json decoded data
    fstructure = json.loads(get_structure(malpdf, exhaustive))
    fcontents = get_contents_obj(malpdf, hexa)
    # TODO scoring
    # fscore = json.loads(get_scores(malpdf))
    fscore = "NotImplemented"
    # TODO related
    # frelated = json.loads(get_related_files(malpdf))
    frelated = "NotImplemented"

    # build the object and then re-encode
    fobj = {"structure": fstructure, "scores": fscore, "scans":
            {}, "contents": fcontents, "related": frelated}
    if vt:
        vt_hash = hash_maker.get_hash_data(malpdf, "md5")
        fobj["scans"]["virustotal"] = get_vt_obj(vt_hash)
    if wepawet:
        fobj["scans"]["wepawet"] = get_wepawet_obj()
    if hashes:
        fobj["hash_data"] = get_hash_obj(malpdf)

    return fobj

if __name__ == '__main__':
    main()
