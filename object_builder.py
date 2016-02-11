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

SUSPECT_KEYWORDS = ('/ObjStm',
                    '/JS',
                    '/JavaScript',
                    '/AA',
                    '/OpenAction',
                    '/AcroForm',
                    '/JBIG2Decode',
                    '/RichMedia',
                    '/Launch',
                    '/EmbeddedFile',
                    '/XFA')
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
    oParser.add_argument(
        '-a', '--all', action='store_true', default=False,
        help='Dump all objects from PDF (Implies high volume of ouput)')
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
                       exhaustive=options.exhaustive, hexa=options.hexa,
                       allobjects=options.all)
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
        log.error(
            "Setup your VirusToal API key at the beginning of the script")
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
    return hash_maker.get_hash_object(file)


def get_contents_obj(file, hexa):
    return {'objects': get_indirect_objects2json(file, hexa)}


# TODO this function should use get_indirect_objects()
def get_indirect_objects2json(file, hexa):
    oPDFParser = pdfparser.cPDFParser(file)
    indirect_objects = []

    while True:
        object = oPDFParser.GetObject()
        if object != None:
            if object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                indirect_objects.append(pdfparser.content2JSON(object, hexa))
        else:
            break

    return indirect_objects


def obj2json(obj, hexa):
    return pdfparser.content2JSON(obj, hexa)


def get_indirect_objects(file):
    oPDFParser = pdfparser.cPDFParser(file)
    indirect_objects = []

    while True:
        object = oPDFParser.GetObject()
        if object != None:
            if object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                indirect_objects.append(object)
        else:
            break

    return indirect_objects


def filter_suspect_objects(indirect_objects, suspect_keywords):
    suspect_objects = []
    raw_results = []
    json_results = []
    for obj in indirect_objects:
        for word in suspect_keywords:
            if obj.Contains(word):
                suspect_objects.append(obj)

    for obj in suspect_objects:
        references = obj.GetReferences()
        refarray = []
        for ref in references:
            refarray.append(ref)
        raw_results.append({"suspect_obj": obj, "references": refarray})
        json_results.append({"suspect_obj": obj2json(obj, False), "references": refarray})

    return json_results, raw_results


# TODO object from GetReferences are not xmlDoc so you cant content2JSON on it
#  -> So this function does not work, ah
def suspect_objects2json(suspect_objects):
    results = []
    for dicobj in suspect_objects:
        obj = dicobj.get("suspect_obj")
        refarray = dicobj.get("references")
        refjson = []
        for ref in refarray:
            refjson.append(obj2json(ref))
        results.append({"suspect_obj": obj2json(obj), "references": refjson})

    return results


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
              hexa=False, allobjects=False):

    # get the json decoded data
    fstructure = json.loads(get_structure(malpdf, exhaustive))
    if not allobjects:
        (fcontents, raw_fcontents) = filter_suspect_objects(
            get_indirect_objects(malpdf), SUSPECT_KEYWORDS)
    else:
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
        fobj["hash"] = get_hash_obj(malpdf)

    return fobj

if __name__ == '__main__':
    main()
