#findevilinfo
__author__ = "Tyler Halfpop"
__version__ = "0.1"
__license__ = "MIT"

VT_API_KEY = "INSERT_VT_API_KEY_HERE"
YARA_RULES_DIR = "INSERT_YARA_RULES_DIR_HERE"

import os
import sys
import pefile
import ssl
import json
import urllib
import urllib2
import math
import yara
from hashlib import sha256

def get_hash(input_file):
    with open(input_file, "rb") as open_file:
        return sha256(open_file.read()).hexdigest()

def get_VT_verdict(file_hash):
    """ Gets the VirusTotal number of hits from VirusTotal example
    https://www.virustotal.com/en/documentation/public-api/#getting-file-scans
    """
    try:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": file_hash, "apikey": VT_API_KEY}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json_object = response.read()
        response_dict = json.loads(json_object)
        verdict = "{} / {}".format(response_dict.get("positives", {}),
                             response_dict.get("total", {}))
        return verdict
    except Exception as e:
        print "Exception: {}".format(e)

def check_signed(input_file):
    """ Check if a PE file is signed using pefile adapted from disitool by Didier Stevens
    https://blog.didierstevens.com/programs/disitool/
    """
    pe =  pefile.PE(input_file)
    addr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    if addr == 0:
        return "Unsigned"
    return "Signed"

def get_entropy(input_file):
    """ Gets the entropy of file from Ero Carrerra's Blog
    http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    with open(input_file, "rb") as open_file:
        data = open_file.read()
        if not data: 
            return 0 
        entropy = 0 
        for x in range(256): 
            p_x = float(data.count(chr(x)))/len(data) 
            if p_x > 0: 
                entropy += - p_x*math.log(p_x, 2) 
    return entropy

def carve(input_file):
    """Carve PE files from segments adapted from Alexander Hanel's blog
    https://hooked-on-mnemonics.blogspot.com/2013/01/pe-carvpy.html
    """
    with open(input_file, "rb") as mem_dump:
        c = 1
        # For each address that contains MZ
        for y in [tmp.start() for tmp in re.finditer('\x4d\x5a',mem_dump.read())]:
            mem_dump.seek(y)
            try:
                pe = pefile.PE(data=self.fileH.read())
            except:
                continue 
            # Determine file ext
            if pe.is_dll() == True:
                ext = 'dll'
            elif pe.is_driver() == True:
                ext = 'sys'
            elif pe.is_exe() == True:
                ext = 'exe'
            else:
                ext = 'bin'

            print '\t*', ext , 'found at offset', hex(y) 

            with open(input_file + "_" + str(count) + '.' + ext, 'wb') as out:
                out.write(pe.trim())

            c += 1
            ext = ''
            mem_dump.seek(0)
            pe.close()

class YaraClass:
    """Main Yara Class that handles walking rule dir, compiling and testing rules, and walking and scanning files.
    """
    def __init__(self):
        """YaraClass initialization that sets verbose, scan and yara directory
        """
        try:
            self.yara_dir = YARA_RULES_DIR
            self.verbose = False
            self.compile()
        except Exception as e:
            print "Init Compile Exception: {}".format(e)

    def compile(self):
        """Walks rule dir, tests rules, and compiles them for scanning.
        """
        try:
            all_rules = {}
            for root, directories, files in os.walk(self.yara_dir):
                for file in files:
                    if "yar" in os.path.splitext(file)[1]:
                        rule_case = os.path.join(root, file)
                        if self.test_rule(rule_case):
                            all_rules[file] = rule_case
            self.rules = yara.compile(filepaths=all_rules)
        except Exception as e:
            print "Compile Exception: {}".format(e)

    def test_rule(self, test_case):
        """Tests rules to make sure they are valid before using them.  If verbose is set will print the invalid rules.
        """
        try:
            yara.compile(filepath=test_case)
            return True
        except:
            if self.verbose:
                print "{} is an invalid rule".format(test_case)
            return False

    def scan(self, scan_file):
        """Scan method that uses compiled rules to scan a file
        """
        try:
            matched_rules = []
            matches = self.rules.match(scan_file)
            for i in matches:
                matched_rules.append(i)
            return matched_rules
        except Exception as e:
            print "Scan Exception: {}".format(e)
            return "ERROR"
