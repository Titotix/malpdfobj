__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import simplejson as json
import urllib
import urllib2
import os
import time
import parser_hash2json
import parser_contents2json
import pdfid_mod
import related_entropy
import hashlib
import hash_maker
import argparse
import logging

DEFAULTDUMPFILE = "malpdfobj_out.json"


def main():
    oParser = argparse.ArgumentParser(description=__description__)
    oParser.add_argument('malpdf', metavar="PDFfile",
                         help='PDF file to build an object from')
    oParser.add_argument('-f', "--file",
                         help='file to dump results')
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
            log.error("Install mongodb before to use it")
            sys.exit()
        con = connect_to_mongo("localhost", 27017, "pdfs", "malware")

    malpdf = os.path.abspath(options.malpdf)

    output = build_obj(malpdf, vt=options.virustotal,
                       wepawet=options.wepawet, hashes=options.hashes,
                       exhaustive=options.exhaustive)
    if options.mongo:
        con.insert(json.loads(output))
    elif options.file:
        dump_fh = open(dumpfile, 'w')
        dump_fh.write(output)
        dump_fh.close()
    else:
        print(output)


def get_vt_obj(file):
    key = 'YOUR_API_KEY'
    url = "https://www.virustotal.com/api/get_file_report.json"
    parameters = {"resource": file, "key": key}
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
        vtobj = {'report': {'results': {'scanners': []}}}

    return json.dumps(vtobj)


def get_wepawet_obj():
    # submission script exist on wepawet website, but getting result need web
    # scrapping
    log.error("Wepawet is not implemented")
    return "null"


def get_structure(file, allKeywords):
    structureobj = pdfid_mod.PDFiD2JSON(
        pdfid_mod.PDFiD(file, allKeywords, True, False, True), True)
    return structureobj


def get_scores(file):
    scoreobj = pdfid_mod.Score2JSON(
        pdfid_mod.PDFiD(file, False, True, False, True))
    return scoreobj


def get_object_details(file):
    objdetails = parser_hash2json.conversion(file)
    return objdetails


def get_hash_obj(file):
    hashes = hash_maker.get_hash_object(file)
    data = {'file': hashes}
    return json.dumps(data)


def get_contents_obj(file):
    objcontents = json.loads(parser_contents2json.contents(file))
    data = {'objects': objcontents}
    return json.dumps(data)


def get_related_files(file):
    related_results = related_entropy.shot_caller(file)
    return json.dumps(related_results)


def connect_to_mongo(host, port, database, collection):
    connection = Connection(host, port)
    db = connection[database]
    collection = db[collection]
    return collection


def kill_database_connection(conn):  # 9b+
    conn.commit()
    conn.close()


def build_obj(malpdf, vt=False, wepawet=False, hashes=False, exhaustive=False):

    # get the json decoded data
    fstructure = json.loads(get_structure(malpdf, allKeywords=exhaustive))
    fcontents = json.loads(get_contents_obj(malpdf))
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
        fvt = json.loads(get_vt_obj(vt_hash))
        fobj["scans"]["virustotal"] = fvt
    if wepawet:
        fwepawet = json.loads(get_wepawet_obj())
        fobj["scans"]["wepawet"] = fwepawet
    if hashes:
        fhashes = json.loads(get_hash_obj(malpdf))
        fobj["hash_data"] = fhashes

    return json.dumps(fobj)


if __name__ == '__main__':
    main()
