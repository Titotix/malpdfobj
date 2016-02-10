import pdfparser
import simplejson as json


def contents(file, hexa):
    PDF_ELEMENT_INDIRECT_OBJECT = 2
    oPDFParser = pdfparser.cPDFParser(file)
    content_json_objs = []

    while True:
        object = oPDFParser.GetObject()
        if object != None:
            if object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                content_json_objs.append(pdfparser.content2JSON(object, hexa))
        else:
            break

    data = {'object': content_json_objs}
    result = json.dumps(data)
    return result
