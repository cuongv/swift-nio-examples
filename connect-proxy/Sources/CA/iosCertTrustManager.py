#! /usr/bin/env python

# Script to manage additional trusted root certificate in the IOS simulator
#
# Allows to add/list/delete/export trusted root certificates to the IOS simulator
# TrustStore.sqlite3 file.
#
# Additionally, root certificates added to a device can be listed and exported from
# a device backup
#
# type ./iosCertTrustManager.py -h for help
#
#
# This script contains code derived from Python-ASN1 to parse and re-encode
# ASN1. The following notice is included:
#
# Python-ASN1 is free software that is made available under the MIT license.
# Consult the file "LICENSE" that is
# distributed together with this file for the exact licensing terms.
#
# Python-ASN1 is copyright (c) 2007-2008 by Geert Jansen <geert@boskant.nl>.
# see https://github.com/geertj/python-asn1

import os
import sys
import argparse
import sqlite3
import ssl
import hashlib
import subprocess
import string
import binascii
import plistlib

#----------------------------------------------------------------------
# A simple ASN1 decoder/encoder based on Python-ASN1
#----------------------------------------------------------------------

class ASN1:
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13

    TypeConstructed = 0x20
    TypePrimitive = 0x00

    ClassUniversal = 0x00
    ClassApplication = 0x40
    ClassContext = 0x80
    ClassPrivate = 0xc0

class Error(Exception):
    """ASN1 error"""


class Encoder(object):
    """A simple ASN.1 encoder. Uses DER encoding."""

    def __init__(self):
        """Constructor."""
        self.m_stack = None

    def start(self):
        """Start encoding."""
        self.m_stack = [[]]

    def enter(self, nr, cls):
        """Start a constructed data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        self._emit_tag(nr, ASN1.TypeConstructed, cls)
        self.m_stack.append([])

    def leave(self):
        """Finish a constructed data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if len(self.m_stack) == 1:
            raise Error, 'Tag stack is empty.'
        value = ''.join(self.m_stack[-1])
        del self.m_stack[-1]
        self._emit_length(len(value))
        self._emit(value)

    def write(self, value, nr, typ, cls):
        """Write a primitive data value."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        self._emit_tag(nr, typ, cls)
        self._emit_length(len(value))
        self._emit(value)

    def output(self):
        """Return the encoded output."""
        if self.m_stack is None:
            raise Error, 'Encoder not initialized. Call start() first.'
        if len(self.m_stack) != 1:
            raise Error, 'Stack is not empty.'
        output = ''.join(self.m_stack[0])
        return output

    def _emit_tag(self, nr, typ, cls):
        """Emit a tag."""
        if nr < 31:
            self._emit_tag_short(nr, typ, cls)
        else:
            self._emit_tag_long(nr, typ, cls)

    def _emit_tag_short(self, nr, typ, cls):
        """Emit a short (< 31 bytes) tag."""
        assert nr < 31
        self._emit(chr(nr | typ | cls))

    def _emit_tag_long(self, nr, typ, cls):
        """Emit a long (>= 31 bytes) tag."""
        head = chr(typ | cls | 0x1f)
        self._emit(head)
        values = []
        values.append((nr & 0x7f))
        nr >>= 7
        while nr:
            values.append((nr & 0x7f) | 0x80)
            nr >>= 7
        values.reverse()
        values = map(chr, values)
        for val in values:
            self._emit(val)

    def _emit_length(self, length):
        """Emit length octects."""
        if length < 128:
            self._emit_length_short(length)
        else:
            self._emit_length_long(length)

    def _emit_length_short(self, length):
        """Emit the short length form (< 128 octets)."""
        assert length < 128
        self._emit(chr(length))

    def _emit_length_long(self, length):
        """Emit the long length form (>= 128 octets)."""
        values = []
        while length:
            values.append(length & 0xff)
            length >>= 8
        values.reverse()
        values = map(chr, values)
        # really for correctness as this should not happen anytime soon
        assert len(values) < 127
        head = chr(0x80 | len(values))
        self._emit(head)
        for val in values:
            self._emit(val)

    def _emit(self, s):
        """Emit raw bytes."""
        assert isinstance(s, str)
        self.m_stack[-1].append(s)


class Decoder(object):
    """A minimal ASN.1 decoder. Understands BER (and DER which is a subset)."""

    def __init__(self):
        """Constructor."""
        self.m_stack = None
        self.m_tag = None

    def start(self, data):
        """Start processing `data'."""
        if not isinstance(data, str):
            raise Error, 'Expecting string instance.'
        self.m_stack = [[0, data]]
        self.m_tag = None

    def peek(self):
        """Return the value of the next tag without moving to the next
        TLV record."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if self._end_of_input():
            return None
        if self.m_tag is None:
            self.m_tag = self._read_tag()
        return self.m_tag

    def read(self):
        """Read a simple value and move to the next TLV record."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if self._end_of_input():
            return None
        tag = self.peek()
        length = self._read_length()
        value = self._read_value(tag[0], length)
        self.m_tag = None
        return (tag, value)

    def eof(self):
        """Return True if we are end of input."""
        return self._end_of_input()

    def enter(self):
        """Enter a constructed tag."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        nr, typ, cls = self.peek()
        if typ != ASN1.TypeConstructed:
            raise Error, 'Cannot enter a non-constructed tag.'
        length = self._read_length()
        bytes = self._read_bytes(length)
        self.m_stack.append([0, bytes])
        self.m_tag = None

    def leave(self):
        """Leave the last entered constructed tag."""
        if self.m_stack is None:
            raise Error, 'No input selected. Call start() first.'
        if len(self.m_stack) == 1:
            raise Error, 'Tag stack is empty.'
        del self.m_stack[-1]
        self.m_tag = None

    def _read_tag(self):
        """Read a tag from the input."""
        byte = self._read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f
        if nr == 0x1f:
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
        return (nr, typ, cls)

    def _read_length(self):
        """Read a length from the input."""
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise Error, 'ASN1 syntax error'
            bytes = self._read_bytes(count)
            bytes = [ ord(b) for b in bytes ]
            length = 0L
            for byte in bytes:
                length = (length << 8) | byte
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, nr, length):
        """Read a value from the input."""
        bytes = self._read_bytes(length)
        value = bytes
        return value

    def _read_byte(self):
        """Return the next input byte, or raise an error on end-of-input."""
        index, input = self.m_stack[-1]
        try:
            byte = ord(input[index])
        except IndexError:
            raise Error, 'Premature end of input.'
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):
        """Return the next `count' bytes of input. Raise error on
        end-of-input."""
        index, input = self.m_stack[-1]
        bytes = input[index:index+count]
        if len(bytes) != count:
            raise Error, 'Premature end of input.'
        self.m_stack[-1][0] += count
        return bytes

    def _end_of_input(self):
        """Return True if we are at the end of input."""
        index, input = self.m_stack[-1]
        assert not index > len(input)
        return index == len(input)

#----------------------------------------------------------------------
# Certificate class
#----------------------------------------------------------------------

class Certificate:
    """Represents a loaded certificate
    """
    def __init__(self):
        self._init_data()

    def _init_data(self):
        self._data = None
        self._subject = None
        self._filepath = None

    def load_PEMfile(self, certificate_path):
        """Load a certificate from a file in PEM format
        """
        self._init_data()
        self._filepath = certificate_path
        with open(self._filepath, "r") as inputFile:
            PEMdata = inputFile.read()
        # convert to binary (DER format)
        self._data = ssl.PEM_cert_to_DER_cert(PEMdata)

    def save_PEMfile(self, certificate_path):
        """Save a certificate to a file in PEM format
        """
        self._filepath = certificate_path
        # convert to text (PEM format)
        PEMdata = ssl.DER_cert_to_PEM_cert(self._data)
        with open(self._filepath, "w") as output_file:
            output_file.write(PEMdata)

    def load_data(self, data):
        self._init_data()
        self._data = data

    def get_data(self):
        return self._data

    def get_fingerprint(self, hash):
        if self._data is None:
            return
        sha = hashlib.sha1() if hash == 'sha1' else hashlib.sha256()
        sha.update(self._data)
        return sha.digest()

    def get_subject(self):
        """Get the certificate subject in human readable one line format
        """
        if self._data != None:
            # use openssl to extract the subject text in single line format
            possl = subprocess.Popen(['openssl',  'x509', '-inform',  'DER',  '-noout',  '-subject', '-nameopt', 'oneline'],
                shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
            subjectText, error_text = possl.communicate(self.get_data())
            return subjectText
        return None

    def get_subject_ASN1(self):
        """Get the certificate subject in ASN1 encoded format as expected for the trusted certificate keychain store
        """
        if self._subject == None and self._data != None:
            self._subject = bytearray()
            decoder = Decoder()
            decoder.start(self._data)
            decoder.enter()
            decoder.enter()
            tag, value = decoder.read()  # read version
            tag, value = decoder.read()  # serial
            tag, value = decoder.read()
            tag, value = decoder.read()  # issuer
            tag, value = decoder.read()  # date
            decoder.enter() # enter in subject
            encoder = Encoder()
            encoder.start()
            self._process_subject(decoder, encoder)
            self._subject = encoder.output()
        return self._subject

    def _process_subject(self, input, output, indent=0):
        # trace = sys.stdout
        while not input.eof():
            tag = input.peek()
            if tag[1] == ASN1.TypePrimitive:
                tag, value = input.read()
                if tag[0] == ASN1.PrintableString:
                    value = string.upper(value)
                output.write(value, tag[0], tag[1], tag[2])
                #trace.write(' ' * indent)
                #trace.write('[%s] %s (value %s)' %
                #         (strclass(tag[2]), strid(tag[0]), repr(value)))
                #trace.write('\n')
            elif tag[1] == ASN1.TypeConstructed:
                #trace.write(' ' * indent)
                #trace.write('[%s] %s:\n' % (strclass(tag[2]), strid(tag[0])))
                input.enter()
                output.enter(tag[0], tag[2])
                self._process_subject(input, output, indent+2)
                output.leave()
                input.leave()

#----------------------------------------------------------------------
# TrustStore.sqlite3 handling
#----------------------------------------------------------------------

class TrustStore:
    """Represents the trusted certificate store
    """
    def __init__(self, path, title=None, always_yes=True):
        self._path = path
        self._hash = None
        self.always_yes = always_yes
        if title:
            self._title = title
        else:
            self._title = path
        self._tset = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"\
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"\
            "<plist version=\"1.0\">\n"\
            "<array/>\n"\
            "</plist>\n"
        #with open('cert_tset.plist', "rb") as inputFile:
        #    self._tset = inputFile.read()

    def is_valid(self):
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        row = c.execute('SELECT count(*) FROM sqlite_master WHERE type=\'table\' AND name=\'tsettings\'').fetchone()
        if row[0] == 0:
            conn.close()
            return False
        c = conn.cursor()
        row = c.execute('SELECT sql FROM sqlite_master WHERE name=\'tsettings\'').fetchone()
        self._hash = 'sha256' if 'sha256' in row[0] else 'sha1'
        conn.close()
        return True

    def _add_record(self, sha, subj, tset, data):
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM tsettings WHERE subj=?', [sqlite3.Binary(subj)])
        row = c.fetchone()
        if row[0] == 0:
            c.execute('INSERT INTO tsettings (' + self._hash + ', subj, tset, data) VALUES (?, ?, ?, ?)', [sqlite3.Binary(sha), sqlite3.Binary(subj), sqlite3.Binary(tset), sqlite3.Binary(data)])
            print '  Certificate added'
        else:
            c.execute('UPDATE tsettings SET ' + self._hash + '=?, tset=?, data=? WHERE subj=?', [sqlite3.Binary(sha), sqlite3.Binary(tset), sqlite3.Binary(data), sqlite3.Binary(subj)])
            print '  Existing certificate replaced'
        conn.commit()
        conn.close()

    def _loadBlob(self, baseName, name):
        with open(baseName + '_' + name + '.bin', 'rb') as inputFile:
            return inputFile.read()

    def _saveBlob(self, baseName, name, data):
        with open(baseName + '_' + name + '.bin', 'wb') as outputFile:
            outputFile.write(data)

    def add_certificate(self, certificate):
        # this also populates self._hash
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        self._add_record(certificate.get_fingerprint(self._hash), certificate.get_subject_ASN1(),
            self._tset, certificate.get_data())

    def export_certificates(self, base_filename):
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        index = 1
        print
        print self._title
        for row in c.execute('SELECT subj, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[1])
            cert.save_PEMfile(base_filename + "_" + str(index) + ".crt")
            index = index + 1
        conn.close()

    def export_certificates_data(self, base_filename):
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        index = 1
        for row in c.execute('SELECT subj, tset, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[2])
            base_filename2 = base_filename + "_" + str(index)
            self._saveBlob(base_filename2, 'subj', row[0])
            self._saveBlob(base_filename2, 'tset', row[1])
            self._saveBlob(base_filename2, 'data', row[2])
        conn.close()

    def import_certificate_data(self, base_filename):
        # this also populates self._hash
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        certificateSubject = self._loadBlob(base_filename, 'subj')
        certificateTSet = self._loadBlob(base_filename, 'tset')
        certificateData = self._loadBlob(base_filename, 'data')
        cert = Certificate()
        cert.load_data(certificateData)
        certificateSha = cert.get_fingerprint(self._hash)

        self._add_record(certificateSha, certificateSubject, certificateTSet, certificateData)

    def list_certificates(self):
        print
        print self._title
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        for row in c.execute('SELECT data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[0])
            print "  ", cert.get_subject()
        conn.close()

    def delete_certificates(self):
        if not self.is_valid():
            print "  Invalid TrustStore.sqlite3"
            return
        conn = sqlite3.connect(self._path)
        c = conn.cursor()
        print
        print self._title
        todelete = []
        for row in c.execute('SELECT subj, data FROM tsettings'):
            cert = Certificate()
            cert.load_data(row[1])
            todelete.append(row[0])
        for item in todelete:
            c.execute('DELETE FROM tsettings WHERE subj=?', [item])
        conn.commit()
        conn.close()


#----------------------------------------------------------------------
# Simulator access
#----------------------------------------------------------------------

class Simulator:
    """Represents an instance of an simulator folder
    """
    simulatorDir = os.getenv('HOME') + "/Library/Developer/CoreSimulator/Devices/"
    trustStorePaths = [
        "/data/private/var/protected/trustd/private/TrustStore.sqlite3",
        "/data/Library/Keychains/TrustStore.sqlite3",
    ]
    runtimeName = "com.apple.CoreSimulator.SimRuntime."

    def __init__(self, simulatordir):
        self._is_valid = False
        infofile = simulatordir + "/device.plist"
        if os.path.isfile(infofile):
            info = plistlib.readPlist(infofile)
            runtime = info["runtime"]
            if runtime.startswith(self.runtimeName):
                self.version = runtime[len(self.runtimeName):].replace("-", ".")
            else:
                self.version = runtime
            self.title = info["name"] + " " + self.version
            for path in self.trustStorePaths:
                self.truststore_file = simulatordir + path
                if os.path.isfile(self.truststore_file):
                    self._is_valid = True
                    return

    def is_valid(self):
        return self._is_valid

def simulators():
    """An iterator over the available simulator versions
    """
    for subdir in os.listdir(Simulator.simulatorDir):
        simulatordir = Simulator.simulatorDir + subdir
        if os.path.isdir(simulatordir):
            simulator = Simulator(simulatordir)
            if simulator.is_valid():
                yield simulator


#----------------------------------------------------------------------
# Individual command implementation and main function
#----------------------------------------------------------------------

def import_to_simulator(certificate_filepath, truststore_filepath=None):
    cert = Certificate()
    cert.load_PEMfile(certificate_filepath)
    print cert.get_subject()
    if truststore_filepath:
        tstore = TrustStore(truststore_filepath, always_yes=True)
        tstore.add_certificate(cert)
        return
    for simulator in simulators():
        print "Importing to " + simulator.truststore_file
        tstore = TrustStore(simulator.truststore_file, always_yes=True)
        tstore.add_certificate(cert)

# Main program
# 0 is the path of the current script
# 1 is the certificate path
path = sys.argv[1]
print path
import_to_simulator(path)

