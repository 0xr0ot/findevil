#findevilmem
__author__ = "Tyler Halfpop"
__version__ = "0.1"
__license__ = "MIT"

import os
import sys

import volatility.debug as debug
import volatility.conf as conf
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods

import findevilinfo

class findEvilMem(taskmods.MemDump):
    """Find potential known evil in memory
    """

    def __init__(self, config, *args, **kwargs):
        taskmods.MemDump.__init__(self, config, *args, **kwargs)
        self._config.DUMP_DIR = os.getcwd() + os.sep + "dump_tmp"
        if not os.path.exists(self._config.DUMP_DIR):
            os.mkdir(self._config.DUMP_DIR)
            print "Creating Dump Dir {}".format(str(self._config.DUMP_DIR))
        else:
            print "Dump Dir Already Exists {}".format(str(self._config.DUMP_DIR))

    def render_text(self, outfd, data):
        """ Dump process memory and check for evil
        https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/taskmods.py
        """

        self.table_header(outfd,
                          [("Name", "20"),
                           ("Result", "25"),
                           ("Verdict", "8"),
                           ("Signed", "8"),
                           ("Entropy", "12")])

        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()

            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    if data == None:
                        if self._config.verbose:
                            outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} Size: 0x{1:x}\n".format(p[0], p[1]))
                    else:
                        output_file = os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp")
                        with open(output_file, 'wb') as f:
                            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))
                            f.write(data)
                        findevilinfo.carve(output_file)
            else:
                outfd.write("Unable to read pages for task.\n")
                
        """
        try:
            for root, directories, files in os.walk(self._config.DUMP_DIR):
                for file in files:
                    dumped_file = os.path.join(root,file)
                    
        except Exception as e:
            print "Exception: {}".format(e)
        """

