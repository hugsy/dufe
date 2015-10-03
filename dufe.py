#!/usr/bin/env python2
#
# DUFE : Dummiest Universal Fuzzer Ever
#
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
import resource
import glob
import multiprocessing

import mutators
import fuzzrange

__author__ = '@hugsy'
__version__ = 0.01
__doc__ = """Possibly the dummiest multi purpose fuzzer"""



class ConfigParserWrapper:

    def __init__(self):
        return

    @staticmethod
    def new(config_file):
        class ConfigSession(object):
            pass

        if sys.version_info.major == 2:
            CP = __import__("ConfigParser")
        elif sys.version_info.major == 3:
            CP = __import__("configparser")
        else:
            raise Exception("Unknown Python version")

        conf = CP.ConfigParser()
        conf.read( config_file )
        sess = ConfigSession()
        for key, value in conf.items("Session"):
            setattr(sess, key, value)

        return sess


class FuzzLoggingFormatter(logging.Formatter):
    def __init__(self):
        fmt = '%(asctime)s %(name)-7s %(levelname)s : %(message)s'
        logging.Formatter.__init__(self, fmt, datefmt='%H:%M:%S')
        return


def hexdump(src, length=0x10):
    f=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    n=0
    result=''

    while src:
       s,src = src[:length],src[length:]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
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


def spawn_process(sess, fname):
    try:
        cmd = sess.command.replace( sess.template_file, fname )
        sess.logger.debug("Executing command: %s" % cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        pid = p.pid
        p.wait()
        retcode = p.returncode
        if b"Segmentation fault" in err:
            sess.logger.debug("Moving coredump in '%s/'" % sess.core_dir)
            subprocess.call(["mv", ] + glob.glob("*.core") + [sess.core_dir, ])
            raise Exception(err.strip())

    except Exception as e:
        sess.logger.warning("[%d] '%s' : raised '%s'" % (pid, cmd, e,))

    return (pid, retcode, cmd)


def mangle_data(data, fuzzblob, fuzzrange):
    d = copy.deepcopy(data)
    return b"".join( [d[:fuzzrange.start], fuzzblob, d[fuzzrange.end+1:]] )


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
            print("* %s" % key)
    return


def init_logger(sess, quiet_mode):
    fhandler = logging.FileHandler( sess.logfile.format(date=int(time.time())) )
    fhandler.setFormatter( FuzzLoggingFormatter() )
    shandler = logging.StreamHandler()
    shandler.setFormatter( FuzzLoggingFormatter() )
    log = logging.getLogger( 'fuzzer' )
    log.setLevel( logging.INFO )
    log.addHandler( fhandler )
    if not quiet_mode: log.addHandler( shandler )
    setattr(sess,"logger", log)
    return


def main():
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument("-q", "--quiet",    help="Do not print log event on stdout", action="store_true", default=False)
    parser.add_argument("-c", "--config",   help="Path to fuzz config file", type=str)
    parser.add_argument("--cpu",            help="Number of CPU to dedicate to fuzz", default=multiprocessing.cpu_count()-1, type=int)
    parser.add_argument("-l", "--list",     help="Display available mutators and exit", action="store_true")
    parser.add_argument("-V", "--version",  help="Show version", action="version", version="%(prog)s " + "%.2f" % __version__)
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
    sess = ConfigParserWrapper.new( args.config )

    # init logger
    init_logger(sess, args.quiet)

    # modify system resource
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

    # init fuzz ranges
    ranges = ast.literal_eval( sess.ranges )
    fuzzranges = []
    items_generator = ranges.iteritems() if sys.version_info.major == 2 else ranges.items()
    for key, value in items_generator:
        current_range = fuzzrange.FuzzRange(key, value)
        if len(current_range.mutators) > 0:
            sess.logger.info("New FuzzRange created: %s" % str(current_range))
            fuzzranges.append( current_range )

    # map data from template in memory
    template = sess.template_file
    original_data = read_file( template )
    sess.logger.info("Read template file '%s' (length=%d bytes)" % (template, len(original_data)))
    # sess.logger.debug("Original data:\n%s", hexdump(original_data).strip())

    # create a pool of workers
    setattr(sess, "workers", [])
    setattr(sess, "workers_lock", multiprocessing.Lock())
    setattr(sess, "max_workers", args.cpu)
    setattr(sess, "worker_id", 0)

    # sort fuzzranges by range.start
    fuzzranges.sort( key=lambda x: x.start, reverse=False )

    if args.cpu == multiprocessing.cpu_count():
        sess.logger.warning("You're using all the CPUs available on your system for this fuzz task.")
        sess.logger.warning("This may distablize your system.")

    # start fuzzing
    sess.logger.info("Starting session '%s': cmd='%s' orig='%s' fuzzdir='%s' cpu=%s" % (sess.session_name,
                                                                                        sess.command,
                                                                                        sess.template_file,
                                                                                        sess.fuzzfiles_dir,
                                                                                        sess.max_workers,))

    try:
        fuzz(sess, original_data, fuzzranges)
    except KeyboardInterrupt:
        sess.logger.info("Ending session '%s'" % sess.session_name)

    sess.logger.info("%d tasks executed" % sess.worker_id)
    return




if __name__ == "__main__":
    main()
