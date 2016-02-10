#!/usr/bin/python

__description__ = 'Tool to test a PDF file'
__author__ = 'Didier Stevens'
__version__ = '0.0.11'
__date__ = '2010/04/28'

import optparse
import os
import re
import xml.dom.minidom
import traceback
import math
import operator
import os.path
import sys
import hashlib
import urllib
import random
import simplejson as json

class cBinaryFile:
    def __init__(self, file):
        self.file = file
        if file == "":
            self.infile = sys.stdin
        else:
            self.infile = open(file, 'rb')
        self.ungetted = []

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte:
            self.infile.close()
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if inbytes == '':
            self.infile.close()
        result = self.ungetted + [ord(b) for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, bytes):
        bytes.reverse()
        self.ungetted.extend(bytes)

class cPDFDate:
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == 'D':
            self.state = 1
            return None
        elif self.state == 1:
            if char == ':':
                self.state = 2
                self.digits1 = ''
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char >= '0' and char <= '9':
                    self.digits1 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif char == '+' or char == '-' or char == 'Z':
                self.state = 3
                self.digits2 = ''
                self.TZ = char
                return None
            elif char == '"':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            elif char < '0' or char > '9':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            else:
                self.state = 0
                return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) < 5:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = 'D:' + self.digits1 + self.TZ + self.digits2
                        return self.date
                    else:
                        return None
                else:
                    self.state = 0
                    return None

def fEntropy(countByte, countTotal):
#BSD fucked this up *bug
    x = 0
    if countByte != 0:
        x = float(countByte) / countTotal
    if x > 0:
        return - x * math.log(x, 2)
    else:
        return 0.0

class cEntropy:
    def __init__(self):
        self.allBucket = [0 for i in range(0, 256)]
        self.streamBucket = [0 for i in range(0, 256)]

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        self.nonStreamBucket = map(operator.sub, self.allBucket, self.streamBucket)
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(self.nonStreamBucket)
        return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount, sum(map(lambda x: fEntropy(x, streamCount), self.streamBucket)), nonStreamCount, sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))

class cPDFEOF:
    def __init__(self):
        self.token = ''
        self.cntEOFs = 0
        self.cntCharsAfterLastEOF = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == '' and char == '%':
            self.token += char
            return
        elif self.token == '%' and char == '%':
            self.token += char
            return
        elif self.token == '%%' and char == 'E':
            self.token += char
            return
        elif self.token == '%%E' and char == 'O':
            self.token += char
            return
        elif self.token == '%%EO' and char == 'F':
            self.token += char
            return
        elif self.token == '%%EOF' and (char == '\n' or char == '\r'):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == '\n':
                self.token = ''
            else:
                self.token += char
            return
        elif self.token == '%%EOF\r':
            if char == '\n':
                self.cntCharsAfterLastEOF = 0
            self.token = ''
        else:
            self.token = ''

def FindPDFHeaderRelaxed(oBinaryFile):
    bytes = oBinaryFile.bytes(1024)
    index = ''.join([chr(byte) for byte in bytes]).find('%PDF')
    if index == -1:
        oBinaryFile.ungets(bytes)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if bytes[endHeader] == 10 or bytes[endHeader] == 13:
            break
    oBinaryFile.ungets(bytes[endHeader:])
    return (bytes[0:endHeader], ''.join([chr(byte) for byte in bytes[index:endHeader]]))

def Hexcode2String(char):
    if type(char) == int:
        return '#%02x' % char
    else:
        return char

def SwapCase(char):
    if type(char) == int:
        return ord(chr(char).swapcase())
    else:
        return char.swapcase()

def HexcodeName2String(hexcodeName):
    return ''.join(map(Hexcode2String, hexcodeName))

def SwapName(wordExact):
    return map(SwapCase, wordExact)

def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    if word != '':
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == '/' and allNames:
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == '/':
            lastName = slash + word
        if slash == '':
            if word == 'stream':
                insideStream = True
            if word == 'endstream':
                if insideStream == True and oEntropy != None:
                    for char in 'endstream':
                        oEntropy.removeInsideStream(ord(char))
                insideStream = False
        if fOut != None:
            if slash == '/' and '/' + word in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/JBIG2Decode', '/RichMedia', '/Launch'):
                wordExactSwapped = HexcodeName2String(SwapName(wordExact))
                fOut.write(wordExactSwapped)
                print '/%s -> /%s' % (HexcodeName2String(wordExact), wordExactSwapped)
            else:
                fOut.write(HexcodeName2String(wordExact))
    return ('', [], False, lastName, insideStream)

class cCVE_2009_3459:
    def __init__(self):
        self.count = 0

    def Check(self, lastName, word):
        if (lastName == '/Colors' and word.isdigit() and int(word) > 2^24): # decided to alert when the number of colors is expressed with more than 3 bytes
            self.count += 1

def PDFiD(file, allNames=False, extraData=False, disarm=False, force=False):
    """Example of XML output:
    <PDFiD ErrorOccured="False" ErrorMessage="" Filename="test.pdf" Header="%PDF-1.1" IsPDF="True" Version="0.0.4" Entropy="4.28">
            <Keywords>
                    <Keyword Count="7" HexcodeCount="0" Name="obj"/>
                    <Keyword Count="7" HexcodeCount="0" Name="endobj"/>
                    <Keyword Count="1" HexcodeCount="0" Name="stream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="endstream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="xref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="trailer"/>
                    <Keyword Count="1" HexcodeCount="0" Name="startxref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/Page"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/Encrypt"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JS"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JavaScript"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/AA"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/OpenAction"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/JBIG2Decode"/>
            </Keywords>
            <Dates>
                    <Date Value="D:20090128132916+01'00" Name="/ModDate"/>
            </Dates>
    </PDFiD>
    """

    global hashed
    global filesize #9b+
    global filename
    filename = str(file)
    hashed = hashlib.sha224(file).hexdigest()
    filesize = str(os.path.getsize(file))
    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    insideStream = False
    keywords = ('obj',
                'endobj',
                'stream',
                'endstream',
                'xref',
                'trailer',
                'startxref',
                '/Page',
                '/Encrypt',
                '/ObjStm',
                '/JS',
                '/JavaScript',
                '/AA',
                '/OpenAction',
                '/AcroForm',
                '/JBIG2Decode',
                '/RichMedia',
                '/Launch',
               )
    words = {}
    dates = []
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ''
    xmlDoc = xml.dom.minidom.getDOMImplementation().createDocument(None, "PDFiD", None)
    att = xmlDoc.createAttribute('Version')
    att.nodeValue = __version__
    xmlDoc.documentElement.setAttributeNode(att)
    att = xmlDoc.createAttribute('Filename')
    att.nodeValue = file
    xmlDoc.documentElement.setAttributeNode(att)
    attErrorOccured = xmlDoc.createAttribute('ErrorOccured')
    xmlDoc.documentElement.setAttributeNode(attErrorOccured)
    attErrorOccured.nodeValue = 'False'
    attErrorMessage = xmlDoc.createAttribute('ErrorMessage')
    xmlDoc.documentElement.setAttributeNode(attErrorMessage)
    attErrorMessage.nodeValue = ''

    oPDFDate = None
    oEntropy = None
    oPDFEOF = None
    oCVE_2009_3459 = cCVE_2009_3459()
    try:
        attIsPDF = xmlDoc.createAttribute('IsPDF')
        xmlDoc.documentElement.setAttributeNode(attIsPDF)
        oBinaryFile = cBinaryFile(file)
        if extraData:
            oPDFDate = cPDFDate()
            oEntropy = cEntropy()
            oPDFEOF = cPDFEOF()
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        if disarm:
            (pathfile, extension) = os.path.splitext(file)
            fOut = open(pathfile + '.disarmed' + extension, 'wb')
            for byteHeader in bytesHeader:
                fOut.write(chr(byteHeader))
        else:
            fOut = None
        if oEntropy != None:
            for byteHeader in bytesHeader:
                oEntropy.add(byteHeader, insideStream)
        if pdfHeader == None and not force:
            attIsPDF.nodeValue = 'False'
            return xmlDoc
        else:
            if pdfHeader == None:
                attIsPDF.nodeValue = 'False'
                pdfHeader = ''
            else:
                attIsPDF.nodeValue = 'True'
            att = xmlDoc.createAttribute('Header')
            att.nodeValue = repr(pdfHeader[0:10]).strip("'")
            xmlDoc.documentElement.setAttributeNode(att)
        byte = oBinaryFile.byte()
        while byte != None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= 'A' and charUpper <= 'Z' or charUpper >= '0' and charUpper <= '9':
                word += char
                wordExact.append(char)
            elif slash == '/' and char == '#':
                d1 = oBinaryFile.byte()
                if d1 != None:
                    d2 = oBinaryFile.byte()
                    if d2 != None and (chr(d1) >= '0' and chr(d1) <= '9' or chr(d1).upper() >= 'A' and chr(d1).upper() <= 'F') and (chr(d2) >= '0' and chr(d2) <= '9' or chr(d2).upper() >= 'A' and chr(d2).upper() <= 'F'):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                        if oEntropy != None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF != None:
                            oPDFEOF.parse(d1)
                            oPDFEOF.parse(d2)
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                        if disarm:
                            fOut.write(char)
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                    if disarm:
                        fOut.write(char)
            else:
                oCVE_2009_3459.Check(lastName, word)

                (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                if char == '/':
                    slash = '/'
                else:
                    slash = ''
                if disarm:
                    fOut.write(char)

            if oPDFDate != None and oPDFDate.parse(char) != None:
                dates.append([oPDFDate.date, lastName])

            if oEntropy != None:
                oEntropy.add(byte, insideStream)

            if oPDFEOF != None:
                oPDFEOF.parse(char)

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
    except:
        attErrorOccured.nodeValue = 'True'
        attErrorMessage.nodeValue = traceback.format_exc()

    if disarm:
        fOut.close()

    attEntropyAll = xmlDoc.createAttribute('TotalEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyAll)
    attCountAll = xmlDoc.createAttribute('TotalCount')
    xmlDoc.documentElement.setAttributeNode(attCountAll)
    attEntropyStream = xmlDoc.createAttribute('StreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyStream)
    attCountStream = xmlDoc.createAttribute('StreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountStream)
    attEntropyNonStream = xmlDoc.createAttribute('NonStreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyNonStream)
    attCountNonStream = xmlDoc.createAttribute('NonStreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountNonStream)
    if oEntropy != None:
        (countAll, entropyAll , countStream, entropyStream, countNonStream, entropyNonStream) = oEntropy.calc()
        attEntropyAll.nodeValue = '%f' % entropyAll
        attCountAll.nodeValue = '%d' % countAll
        attEntropyStream.nodeValue = '%f' % entropyStream
        attCountStream.nodeValue = '%d' % countStream
        attEntropyNonStream.nodeValue = '%f' % entropyNonStream
        attCountNonStream.nodeValue = '%d' % countNonStream
    else:
        attEntropyAll.nodeValue = ''
        attCountAll.nodeValue = ''
        attEntropyStream.nodeValue = ''
        attCountStream.nodeValue = ''
        attEntropyNonStream.nodeValue = ''
        attCountNonStream.nodeValue = ''
    attCountEOF = xmlDoc.createAttribute('CountEOF')
    xmlDoc.documentElement.setAttributeNode(attCountEOF)
    attCountCharsAfterLastEOF = xmlDoc.createAttribute('CountCharsAfterLastEOF')
    xmlDoc.documentElement.setAttributeNode(attCountCharsAfterLastEOF)
    if oPDFEOF != None:
        attCountEOF.nodeValue = '%d' % oPDFEOF.cntEOFs
        attCountCharsAfterLastEOF.nodeValue = '%d' % oPDFEOF.cntCharsAfterLastEOF
    else:
        attCountEOF.nodeValue = ''
        attCountCharsAfterLastEOF.nodeValue = ''

    eleKeywords = xmlDoc.createElement('Keywords')
    xmlDoc.documentElement.appendChild(eleKeywords)
    for keyword in keywords:
        eleKeyword = xmlDoc.createElement('Keyword')
        eleKeywords.appendChild(eleKeyword)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = keyword
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('Count')
        att.nodeValue = str(words[keyword][0])
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('HexcodeCount')
        att.nodeValue = str(words[keyword][1])
        eleKeyword.setAttributeNode(att)
    eleKeyword = xmlDoc.createElement('Keyword')
    eleKeywords.appendChild(eleKeyword)
    att = xmlDoc.createAttribute('Name')
    att.nodeValue = '/Colors > 2^24'
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('Count')
    att.nodeValue = str(oCVE_2009_3459.count)
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('HexcodeCount')
    att.nodeValue = str(0)
    eleKeyword.setAttributeNode(att)
    if allNames:
        keys = words.keys()
        keys.sort()
        for word in keys:
            if not word in keywords:
                eleKeyword = xmlDoc.createElement('Keyword')
                eleKeywords.appendChild(eleKeyword)
                att = xmlDoc.createAttribute('Name')
                att.nodeValue = word
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('Count')
                att.nodeValue = str(words[word][0])
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('HexcodeCount')
                att.nodeValue = str(words[word][1])
                eleKeyword.setAttributeNode(att)
    eleDates = xmlDoc.createElement('Dates')
    xmlDoc.documentElement.appendChild(eleDates)
    dates.sort(lambda x, y: cmp(x[0], y[0]))
    for date in dates:
        eleDate = xmlDoc.createElement('Date')
        eleDates.appendChild(eleDate)
        att = xmlDoc.createAttribute('Value')
        att.nodeValue = date[0]
        eleDate.setAttributeNode(att)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = date[1]
        eleDate.setAttributeNode(att)
    return xmlDoc

def PDFiD2String(xmlDoc, force):
    result = 'PDFiD %s %s\n' % (xmlDoc.documentElement.getAttribute('Version'), xmlDoc.documentElement.getAttribute('Filename'))
    if xmlDoc.documentElement.getAttribute('ErrorOccured') == 'True':
        return result + '***Error occured***\n%s\n' % xmlDoc.documentElement.getAttribute('ErrorMessage')
    if not force and xmlDoc.documentElement.getAttribute('IsPDF') == 'False':
        return result + ' Not a PDF document\n'
    result += ' PDF Header: %s\n' % xmlDoc.documentElement.getAttribute('Header')
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        result += ' %-16s %7d' % (node.getAttribute('Name'), int(node.getAttribute('Count')))
        if int(node.getAttribute('HexcodeCount')) > 0:
            result += '(%d)' % int(node.getAttribute('HexcodeCount'))
        result += '\n'
    if xmlDoc.documentElement.getAttribute('CountEOF') != '':
        result += ' %-16s %7d\n' % ('%%EOF', int(xmlDoc.documentElement.getAttribute('CountEOF')))
    if xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF') != '':
        result += ' %-16s %7d\n' % ('After last %%EOF', int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')))
    for node in xmlDoc.documentElement.getElementsByTagName('Dates')[0].childNodes:
        result += ' %-23s %s\n' % (node.getAttribute('Value'), node.getAttribute('Name'))
    if xmlDoc.documentElement.getAttribute('TotalEntropy') != '':
        result += ' Total entropy:           %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('TotalEntropy'), xmlDoc.documentElement.getAttribute('TotalCount'))
    if xmlDoc.documentElement.getAttribute('StreamEntropy') != '':
        result += ' Entropy inside streams:  %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('StreamEntropy'), xmlDoc.documentElement.getAttribute('StreamCount'))
    if xmlDoc.documentElement.getAttribute('NonStreamEntropy') != '':
        result += ' Entropy outside streams: %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('NonStreamEntropy'), xmlDoc.documentElement.getAttribute('NonStreamCount'))
    return result

def PDFiD2CSV(xmlDoc, force):
    result = '%s,' % (xmlDoc.documentElement.getAttribute('Filename')) #filename
    result += '%s,' % xmlDoc.documentElement.getAttribute('Header') #header
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes: #obj,eobj,stream,estream,xref,trailer,sxref
        result += '%d,' % (int(node.getAttribute('Count'))) #page,encrypt,objstm,js,javascript,aa,openaction,acroform,jbig2decode,richmedia,launch,colors
        if int(node.getAttribute('HexcodeCount')) >= 0:
            result += '%d,' % int(node.getAttribute('HexcodeCount'))
    if xmlDoc.documentElement.getAttribute('CountEOF') != '':
        result += '%d,' % (int(xmlDoc.documentElement.getAttribute('CountEOF'))) #count eof
    if xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF') != '':
        result += '%d,' % (int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF'))) #chars after eof
    if xmlDoc.documentElement.getAttribute('TotalEntropy') != '':
        result += '%s,' % (xmlDoc.documentElement.getAttribute('TotalEntropy')) #total ent
        result += '%s,' % (xmlDoc.documentElement.getAttribute('TotalCount')) #total ent bytes
    if xmlDoc.documentElement.getAttribute('StreamEntropy') != '':
        result += '%s,' % (xmlDoc.documentElement.getAttribute('StreamEntropy')) #stream ent
        result += '%s,' % (xmlDoc.documentElement.getAttribute('StreamCount')) #stream ent bytes
    if xmlDoc.documentElement.getAttribute('NonStreamEntropy') != '':
        result += '%s,' % (xmlDoc.documentElement.getAttribute('NonStreamEntropy'))
        result += '%s' % (xmlDoc.documentElement.getAttribute('NonStreamCount'))
    return result
    
def PDFiD2JSON(xmlDoc, force):
    #Get Top Layer Data
    errorOccured = xmlDoc.documentElement.getAttribute('ErrorOccured')
    errorMessage = xmlDoc.documentElement.getAttribute('ErrorMessage')
    filename = xmlDoc.documentElement.getAttribute('Filename')
    header = xmlDoc.documentElement.getAttribute('Header')
    isPdf = xmlDoc.documentElement.getAttribute('IsPDF')
    version = xmlDoc.documentElement.getAttribute('Version')
    entropy = xmlDoc.documentElement.getAttribute('Entropy')

    #extra data
    countEof = xmlDoc.documentElement.getAttribute('CountEOF')
    countChatAfterLastEof = xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')
    totalEntropy = xmlDoc.documentElement.getAttribute('TotalEntropy')
    streamEntropy = xmlDoc.documentElement.getAttribute('StreamEntropy')
    nonStreamEntropy = xmlDoc.documentElement.getAttribute('NonStreamEntropy')
    
    keywords = []
    components = []
    dates = []

    #grab all keywords
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        name = unicode(node.getAttribute('Name'),errors='replace')
        count = int(node.getAttribute('Count'))
        if int(node.getAttribute('HexcodeCount')) > 0:
            hexCount = int(node.getAttribute('HexcodeCount'))
        else:
            hexCount = 0
	if name[0] == '/' and count > 0:
        	keyword = { 'count':count, 'hexcodecount':hexCount, 'name':name }
        	keywords.append(keyword)
	else:
		if count > 0:
			component = { 'count':count, 'hexcodecount':hexCount, 'name':name }
			components.append(component)

    #grab all date information
    for node in xmlDoc.documentElement.getElementsByTagName('Dates')[0].childNodes:
        name = node.getAttribute('Name')
        value = node.getAttribute('Value')
        date = { 'name':name, 'value':value }
        dates.append(date)

    data = { 'filesize': filesize, 'countEof':countEof, 'countChatAfterLastEof':countChatAfterLastEof, 'totalEntropy':totalEntropy, 'streamEntropy':streamEntropy, 'nonStreamEntropy':nonStreamEntropy, 'errorOccured':errorOccured, 'errorMessage':errorMessage, 'filename':filename, 'header':header, 'isPdf':isPdf, 'version':version, 'entropy':entropy, 'keywords': { 'keyword': keywords }, 'dates': { 'date':dates}, 'components': { 'component': components } }
    return json.dumps(data)


def parseCSVtoSQL(csv_list):
    data = csv_list.split(',')

    #hash
    #filesize
    filename = data[0]
    header = data[1]
    obj = data[2]
    obj_hex = data[3]
    eobj = data[4]
    eobj_hex = data[5]
    stream = data[6]
    stream_hex = data[7]
    estream = data[8]
    estream_hex = data[9]
    xref = data[10]
    xref_hex = data[11]
    trailer = data[12]
    trailer_hex = data[13]
    sxref = data[14]
    sxref_hex = data[15]
    
    page = data[16]
    page_hex = data[17]
    encrypt = data[18]
    encrypt_hex = data[19]
    objstm = data[20]
    objstm_hex = data[21]
    js = data[22]
    js_hex = data[23]
    javascript = data[24]
    javascript_hex = data[25]
    aa = data[26]
    aa_hex = data[27]
    openaction = data[28]
    openaction_hex = data[29]
    acroform = data[30]
    acroform_hex = data[31]
    jbig2decode = data[32]
    jbig2decode_hex = data[33]
    richmedia = data[34]
    richmedia_hex = data[35]
    launch = data[36]
    launch_hex = data[37]
    colors = data[38]
    colors_hex = data[39]
    
    eof = data[40]
    chars_eof = data[41]
    total_ent = data[42]
    total_ent_by = data[43]
    stream_ent = data[44]
    stream_ent_by = data[45]
    nonstream_ent = data[46]
    nonstream_ent_by = data[47]

    sql = 'insert into pdf_data_dump values("%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s")' % (hashed, filesize, filename, header, obj, obj_hex, eobj, eobj_hex, stream, stream_hex, estream, estream_hex, xref, xref_hex, trailer, trailer_hex, sxref, sxref_hex, page, page_hex, encrypt, encrypt_hex, objstm, objstm_hex, js, js_hex, javascript, javascript_hex, aa, aa_hex, openaction, openaction_hex, acroform, acroform_hex, jbig2decode, jbig2decode_hex, richmedia, richmedia_hex, launch, launch_hex, colors, colors_hex, eof, chars_eof, total_ent, total_ent_by, stream_ent, stream_ent_by, nonstream_ent, nonstream_ent_by)

    return sql

class cPDFScore:
    def __init__(self, xmlDoc):
        self.total_score = 0
        self.primary_score = 0
        self.secondary_score = 0
        self.obj = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[0].getAttribute('Count')
        self.end_obj = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[1].getAttribute('Count')
        self.stream = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[2].getAttribute('Count')
        self.end_stream = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[3].getAttribute('Count')
        self.pages = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[7].getAttribute('Count')
        self.js = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[10].getAttribute('Count')
        self.javascript = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[11].getAttribute('Count')
        self.jbig2decode = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[15].getAttribute('Count')    
        self.richmedia = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[16].getAttribute('Count')
        self.launch = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[17].getAttribute('Count')
        self.colors = xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes[18].getAttribute('Count')
        
    def calculate_primary(self):
        self.calculate_filesize()
        self.calculate_objects()
        self.calculate_streams()
        self.calculate_pages()
        self.calculate_javascript()
        return self.primary_score

    def calculate_secondary(self):
        self.calculate_jbig2decode()
        self.calculate_richmedia()
        self.calculate_launch()
        self.calculate_colors()
        return self.secondary_score

    def calculate_total(self):
        self.reset()
        self.calculate_primary()
        self.calculate_secondary()
        if self.secondary_score < 0:
            self.secondary_score = 0
        self.total_score = self.primary_score + self.secondary_score
        return self.total_score

    def reset(self):
        self.primary_score = 0
        self.secondary_score = 0
        self.total_score = 0

    def calculate_filesize(self):
        if int(filesize) < 1887436.8:
            self.primary_score += 1 
        else:
            self.primary_score -= 1

    def calculate_objects(self):
        if self.obj == self.end_obj:
            self.primary_score += 1
        else:
            self.primary_score -= 1

    def calculate_streams(self):
        if self.stream == self.end_stream:
            self.primary_score += 1
        else:
            self.primary_score -= 1

    def calculate_pages(self):
        if int(self.pages) >= 1 and int(self.pages) <= 2:
            self.primary_score += 1
        else:
            self.primary_score -= 1

    def calculate_javascript(self):
        if int(self.js) > 0 or int(self.javascript) > 0:
            self.primary_score += 1
        else:
            self.primary_score -= 1

    def calculate_jbig2decode(self):
        if int(self.jbig2decode) > 0:
            self.secondary_score += .5
#        else:
#            self.secondary_score -= .5

    def calculate_richmedia(self):
        if int(self.richmedia) > 0:
            self.secondary_score += 1
#        else:
#            self.secondary_score -= 1

    def calculate_launch(self):
        if int(self.launch) > 0:
            self.secondary_score += .5
#        else:
#            self.secondary_score -= .5

    def calculate_colors(self):
        if int(self.colors) > 0:
            self.secondary_score += .5
#        else:
#            self.secondary_score -= .5

def PDFiD2Score(xmlDoc):
    score = cPDFScore(xmlDoc)
    primary_score = score.calculate_primary()
    secondary_score = score.calculate_secondary()
    total_score = score.calculate_total()

    result = "PS:" + str(primary_score)
    result += " SS:" + str(secondary_score)
    result += " TS:" + str(total_score)
    result += " " + filename

    return result
    
def Score2JSON(xmlDoc):
    score = cPDFScore(xmlDoc)
    primary_score = score.calculate_primary()
    secondary_score = score.calculate_secondary()
    total_score = score.calculate_total()
    
    data = { 'primary': str(primary_score), 'secondary': str(secondary_score), 'total': str(total_score) }

    return json.dumps(data)

def connect_database(host, user, password, database):
	try:
		conn = MySQLdb.connect (host, user, password, database)
		return conn
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)
	
def kill_database_connection(conn):
	conn.commit()
	conn.close()

def Scan(directory, allNames, extraData, disarm, force):
    try:
        if os.path.isdir(directory):
            for entry in os.listdir(directory):
                Scan(os.path.join(directory, entry), allNames, extraData, disarm, force)
        else:
            result = PDFiD2String(PDFiD(directory, allNames, extraData, disarm, force), force)
            print result
            logfile = open('PDFiD.log', 'a')
            print >> logfile, result
            logfile.close()
    except:
        pass

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [pdf-file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--scan', action='store_true', default=False, help='scan the given directory')
    oParser.add_option('-a', '--all', action='store_true', default=False, help='display all the names')
    oParser.add_option('-e', '--extra', action='store_true', default=False, help='display extra data, like dates')
    oParser.add_option('-f', '--force', action='store_true', default=False, help='force the scan of the file, even without proper %PDF header')
    oParser.add_option('-d', '--disarm', action='store_true', default=False, help='disable JavaScript and auto launch')
    oParser.add_option('-x', '--xml', action='store_true', default=False, help='display raw xml')
    oParser.add_option('-j', '--json', action='store_true', default=False, help='display raw json')
    oParser.add_option('-C', '--csv', action='store_true', default=False, help='display csv output')
    oParser.add_option('-D', '--dump', action='store_true', default=False, help='dump output to a database')
    oParser.add_option('-S', '--score', action='store_true', default=False, help='score the PDF based on a rubric')  
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        if options.disarm:
            print 'Option disarm not supported with stdin'
            options.disarm = False
        print PDFiD2String(PDFiD('', options.all, options.extra, options.disarm, options.force), options.force)
    elif len(args) == 1:
        if options.scan:
            Scan(args[0], options.all, options.extra, options.disarm, options.force)
        elif options.xml:
            mydoc = PDFiD(args[0], options.all, options.extra, options.disarm, options.force)
            print mydoc.toxml()
        elif options.json:
            print PDFiD2JSON(PDFiD(args[0], options.all, options.extra, options.disarm, options.force), options.force)
        elif options.csv:
            print PDFiD2CSV(PDFiD(args[0], options.all, options.extra, options.disarm, options.force), options.force)
        elif options.dump:
            csv_list = PDFiD2CSV(PDFiD(args[0], options.all, options.extra, options.disarm, options.force), options.force)
            sql = parseCSVtoSQL(csv_list)
            conn = connect_database('127.0.0.1', 'root', 'password', 'pdf_xray')
            cursor = conn.cursor()
            cursor.execute(sql)
            if cursor.rowcount != 1:
                print "Something went wrong"
            else:
                cursor.close()
		kill_database_connection(conn)
                print "Dump added"
        elif options.score:
            print PDFiD2Score(PDFiD(args[0], options.all, options.extra, options.disarm, options.force))
        else:
            print PDFiD2String(PDFiD(args[0], options.all, options.extra, options.disarm, options.force), options.force)
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    Main()
