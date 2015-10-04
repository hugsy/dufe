#!/usr/bin/env python
#
# DUFE : Dummiest Universal Fuzzer Ever
#
# Works out-of-the-box on Python2 > 2.6 and Python3.x
#

from __future__ import print_function

import ast
import argparse
import sys
import os
import tempfile
import subprocess
import logging
import time
import copy
import platform
import glob
import signal
import shutil
import multiprocessing

import mutators
import fuzzrange


__author__ = '@hugsy'
__version__ = 0.01
__doc__ = """Possibly the dummiest multi purpose fuzzer"""



class Session:

    def __init__(self):
        self.workers = []
        self.workers_lock = multiprocessing.Lock()
        self.max_workers = 0
        self.worker_id = 1
        self.start_time = 0
        self.end_time = 0
        self.incorrect_retcode = 0
        return

    @staticmethod
    def new(config_file):
        if sys.version_info.major == 2:
            CP = __import__("ConfigParser")
        elif sys.version_info.major == 3:
            CP = __import__("configparser")
        else:
            raise Exception("Unknown Python version")

        conf = CP.ConfigParser()
        conf.read( config_file )
        sess = Session()
        for key, value in conf.items("Session"):
            setattr(sess, key, value)

        return sess


class FuzzLoggingFormatter(logging.Formatter):
    def __init__(self):
        fmt = '%(asctime)s %(name)-7s %(levelname)s : %(message)s'
        logging.Formatter.__init__(self, fmt, datefmt='%H:%M:%S')
        return


def hexdump(src, length=0x10):
    if sys.version_info.major == 3:
        f=b''.join([(len(repr(chr(x).encode("utf-8")))==3) and chr(x).encode("utf-8") or b'.' for x in range(256)])
    else:
        f=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    n=0
    result=''

    while src:
       s,src = src[:length],src[length:]
       hexa = b' '.join([b"%02X"%x for x in s]) if sys.version_info.major==3 else ' '.join(["%02X"%ord(x) for x in s])
       s = s.translate(f)
       result += "%04X   %-*s   %s\n" % (n, length*3, hexa, s)
       n+=length

    return result


def write_fuzzfile(sess, data):
    if not hasattr(sess, "use_fuzzfile"):
        fd, fname = tempfile.mkstemp( prefix="fuzzcase_", dir=sess.fuzzfiles_dir )
    else:
        fname = sess.use_fuzzfile
        os.unlink( fname )
        fd = os.open( sess.use_fuzzfile, os.O_WRONLY|os.O_CREAT)

    os.write(fd, data)
    os.close(fd)

    return fname


def sighandler():
    signal.signal(signal.SIGSEGV, handle_sig)
    return

def handle_sig(signum, frame):
    return

def spawn_process(sess, fname):
    try:
        cmd = sess.command.replace( sess.template_file, fname )
        sess.logger.debug("Executing command: %s" % cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=sighandler)
        out, err = p.communicate()
        pid = p.pid
        p.wait()
        retcode = p.returncode

        # check retcode
        if retcode and os.WIFSIGNALED(retcode):
            sig = os.WTERMSIG(retcode)
            if sig == signal.SIGSEGV:
                for f in glob.glob("*.core"):
                    shutil.move(f, sess.core_dir)
                raise Exception("[%d] Killed with SIGSEGV, coredump saved" % pid)

    except Exception as e:
        sess.logger.warning("[%d] '%s': %s" % (pid, cmd, e,))

    return (pid, retcode, cmd)


def insert_fuzzed_data(original_data, fuzzed_data, fuzzrange):
    d = copy.deepcopy(original_data)
    return b"".join( [d[:fuzzrange.start], fuzzed_data, d[fuzzrange.start+len(fuzzed_data)+1:]] )


def replace_with_fuzzed_data(original_data, fuzzed_data, fuzzrange):
    d = copy.deepcopy(original_data)
    return b"".join( [d[:fuzzrange.start], fuzzed_data, d[fuzzrange.end+1:]] )


def mangle_data(original_data, fuzzed_data, fuzzrange):
    return insert_fuzzed_data(original_data, fuzzed_data, fuzzrange)
    #return replace_with_fuzzed_data(original_data, fuzzed_data, fuzzrange)

def start_fuzzcase(session, data):
    try:
        fuzz_filename = write_fuzzfile(session, data )
        pid, retcode, cmd = spawn_process(session, fuzz_filename)
    except KeyboardInterrupt:
        retcode = -1

    if retcode < 128:
        if retcode > 0:
            session.logger.debug("PID=%d (cmd='%s') returned with %d" % (pid, cmd, retcode))
        if not hasattr(session, "keep_fuzzfiles") or session.keep_fuzzfiles not in (True, "True", 1):
            os.unlink( fuzz_filename )
    else:
        session.incorrect_retcode += 1
    return


def fuzz(sess, data, fuzzranges):
    current_range = fuzzranges[0]
    start, end = current_range.start, current_range.end
    replaced_bytes = data[ start:end ]

    for fuzzblob in current_range.get_next_value(replaced_bytes):
        sess.logger.debug("[%d] Current range: %d -> %d, len(blob)=%d" % (len(fuzzranges), start, end, len(fuzzblob)))
        new_data = mangle_data(data, fuzzblob, current_range)

        if len(fuzzranges) > 1:
            next_range = fuzzranges[1]

            sess.logger.debug("Next range: %d -> %d" % (next_range.start, next_range.end))
            delta = next_range.start - current_range.end + 1
            end = start + len(fuzzblob)
            sess.logger.debug("Current range adjusted: %d -> %d, len(blob)=%d" % (start, end, len(fuzzblob)))

            size             = next_range.size
            next_range.start = end + 1 + delta
            next_range.end   = next_range.start + size
            sess.logger.debug("Next range adjusted: %d -> %d" % (next_range.start, next_range.end))

            fuzz(sess, new_data, fuzzranges[1:])

        else:

            if platform.system() == 'Linux':
                if len(sess.workers) >= sess.max_workers:
                    for p in sess.workers:
                        p.join()
                        sess.workers.remove(p)
                        break

                sess.workers_lock.acquire()
                p = multiprocessing.Process(target=start_fuzzcase, args=(sess, new_data))
                sess.workers.append(p)
                sess.worker_id += 1
                sess.workers_lock.release()
                p.start()
            else:
                # multiprocessing does not work on windows
                rc = start_fuzzcase(sess, new_data)

        del new_data
    return


def read_file( fname ):
    with open(fname, 'rb') as f:
        data = f.read()
    return data


def is_readable_file(fname):
    return os.access(fname, os.R_OK)


def show_mutators():
    print ("Available mutators:")
    for key in mutators.__dict__.keys():
        if key.startswith("MUTATOR_"):
            name = key
            doc = mutators.__dict__[key].__doc__ if hasattr(mutators.__dict__[key], "__doc__") else "No description"
            print("* %s: %s" % (key, doc))
    return


def init_logger(sess, args):
    fhandler = logging.FileHandler( sess.logfile.format(date=int(time.time())) )
    fhandler.setFormatter( FuzzLoggingFormatter() )
    shandler = logging.StreamHandler()
    shandler.setFormatter( FuzzLoggingFormatter() )
    log = logging.getLogger( 'fuzzer' )
    if args.debug:
        log.setLevel( logging.DEBUG )
    else:
        log.setLevel( logging.INFO )
    log.addHandler( fhandler )
    if not args.quiet: log.addHandler( shandler )
    sess.logger = log
    return


def main():
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument("-q", "--quiet",    help="Do not print log event on stdout", action="store_true", default=False)
    parser.add_argument("-c", "--config",   help="Path to fuzz config file", type=str)
    parser.add_argument("--cpu",            help="Number of CPU to dedicate to fuzz (defaults to your number of CPU minus 1)", default=multiprocessing.cpu_count()-1, type=int)
    parser.add_argument("-l", "--list",     help="Display available mutators and exit", action="store_true")
    parser.add_argument("-n", "--dry-run",  help="Performs a dry-run: init the structures but do not start fuzzing", action="store_true", default=False, dest="dryrun")
    parser.add_argument("-V", "--version",  help="Show version", action="version", version="%(prog)s " + "%.2f" % __version__)
    parser.add_argument("-d", "--debug",    help="Set the verbosity to DEBUG level", action="store_true", default=False)
    args = parser.parse_args()

    if args.list:
        show_mutators()
        exit(0)

    if not args.config or not is_readable_file(args.config):
        print("A valid config file is required [-c/--config]")
        exit(1)

    if not 1 <= args.cpu <= multiprocessing.cpu_count():
        print("The number of CPUs to use must in [1, %d]" % multiprocessing.cpu_count())
        exit(1)

    # init new session
    sess = Session.new( args.config )
    sess.max_workers = args.cpu

    # init logger
    init_logger(sess, args)

    # modify system resource
    if platform.machine() == "Linux":
        rsc = __import__("resource")
        rsc.setrlimit(resource.RLIMIT_CORE, (-1, -1))

    # init fuzz ranges
    ranges = ast.literal_eval( sess.ranges )
    fuzzranges = []
    items_generator = ranges.iteritems() if sys.version_info.major == 2 else ranges.items()
    for key, value in items_generator:
        current_range = fuzzrange.FuzzRange(key, value)
        if len(current_range.mutators) > 0:
            sess.logger.info("New FuzzRange created: %s" % str(current_range))
            fuzzranges.append( current_range )

    if len(fuzzranges)==0:
        sess.logger.info("Nothing to fuzz...")
        exit(0)

    # map data from template in memory
    template = sess.template_file
    original_data = read_file( template )
    sess.logger.info("Read template file '%s' (length=%d bytes)" % (template, len(original_data)))
    sess.logger.debug("Original data:\n%s", hexdump(original_data).strip())

    # sort fuzzranges by range.start
    fuzzranges.sort( key=lambda x: x.start, reverse=False )

    if args.cpu == multiprocessing.cpu_count():
        sess.logger.warning("You're using all the CPUs available on your system for this fuzz task.")
        sess.logger.warning("This may distabilize your system.")

    if sess.keep_fuzzfiles in ("True", "true", 1, True):
        sess.logger.warning("You have chosen not to delete fuzz test cases generated.")
        sess.logger.warning("This is a dangerous option that may saturate your directory.")

    # start fuzzing
    sess.logger.info("Starting session '%s': cmd='%s' orig='%s' fuzzdir='%s' cpu=%s" % (sess.session_name,
                                                                                        sess.command,
                                                                                        sess.template_file,
                                                                                        sess.fuzzfiles_dir,
                                                                                        sess.max_workers,))
    sess.start_time = time.time()
    try:
        if not args.dryrun:
            fuzz(sess, original_data, fuzzranges)
    except KeyboardInterrupt:
        pass
    sess.end_time = time.time()

    execution_time = sess.end_time - sess.start_time
    sess.logger.info("Ending session '%s'" % sess.session_name)
    sess.logger.info("%d incorrect retcodes were found" % sess.incorrect_retcode)
    sess.logger.info("%d tasks executed" % sess.worker_id)
    sess.logger.info("Execution time: %.4f sec (average=%.4f sec/task)" % (execution_time,
                                                                           execution_time/sess.worker_id))
    return


if __name__ == "__main__":
    main()
