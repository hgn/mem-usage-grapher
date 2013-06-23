#!/usr/bin/env python

# Licence: LGPLv2
# Author: Hagen Paul Pfeifer
# Original Author:  P@draigBrady.com


import getopt
import time
import errno
import os
import sys
import hashlib
import datetime



# The following exits cleanly on Ctrl-C or EPIPE
# while treating other exceptions as before.
def std_exceptions(etype, value, tb):
    sys.excepthook = sys.__excepthook__
    if issubclass(etype, KeyboardInterrupt):
        pass
    elif issubclass(etype, IOError) and value.errno == errno.EPIPE:
        pass
    else:
        sys.__excepthook__(etype, value, tb)
sys.excepthook = std_exceptions


PAGESIZE = os.sysconf("SC_PAGE_SIZE") / 1024 #KiB
our_pid = os.getpid()

have_pss = 0

class Proc:
    def __init__(self):
        self.proc = '/proc'

    def path(self, *args):
        return os.path.join(self.proc, *(str(a) for a in args))

    def open(self, *args):
        try:
            return open(self.path(*args))
        except (IOError, OSError):
            val = sys.exc_info()[1]
            if (val.errno == errno.ENOENT or
                val.errno == errno.EPERM):
                raise LookupError

proc = Proc()


def parse_options():
    try:
        long_options = ['split-args', 'help']
        opts, args = getopt.getopt(sys.argv[1:], "sghp:w:", long_options)
    except getopt.GetoptError:
        sys.stderr.write(help())
        sys.exit(3)

    # ps_mem.py options
    split_args = False
    pids_to_show = None
    watch = None
    graph = False

    for o, a in opts:
        if o in ('-s', '--split-args'):
            split_args = True
        if o in ('-h', '--help'):
            sys.stdout.write(help())
            sys.exit(0)
        if o in ('-p',):
            try:
                pids_to_show = [int(x) for x in a.split(',')]
            except:
                sys.stderr.write(help())
                sys.exit(3)
        if o in ('-w',):
            try:
                watch = int(a)
            except:
                sys.stderr.write(help())
                sys.exit(3)
        if o in ('-g', '--graph'):
            graph = True

    return (split_args, pids_to_show, watch, graph)

def help():
    help_msg = 'ps_mem.py - Show process memory usage\n'\
    '\n'\
    '-h                                 Show this help\n'\
    '-w <N>                             Measure and show process memory every N seconds\n'\
    '-p <pid>[,pid2,...pidN]            Only show memory usage PIDs in the specified list\n'
    '-g                                 Generate memory data for gnuplot processing\n'

    return help_msg

#(major,minor,release)
def kernel_ver():
    kv = proc.open('sys/kernel/osrelease').readline().split(".")[:3]
    last = len(kv)
    if last == 2:
        kv.append('0')
    last -= 1
    for char in "-_":
        kv[last] = kv[last].split(char)[0]
    try:
        int(kv[last])
    except:
        kv[last] = 0
    return (int(kv[0]), int(kv[1]), int(kv[2]))


#return Private,Shared
#Note shared is always a subset of rss (trs is not always)
def getMemStats(pid):
    global have_pss
    mem_id = pid #unique
    Private_lines = []
    Shared_lines = []
    Pss_lines = []
    Rss = (int(proc.open(pid, 'statm').readline().split()[1])
           * PAGESIZE)
    if os.path.exists(proc.path(pid, 'smaps')): #stat
        digester = hashlib.md5()
        for line in proc.open(pid, 'smaps').readlines(): #open
            # Note we checksum smaps as maps is usually but
            # not always different for separate processes.
            digester.update(line.encode('latin1'))
            if line.startswith("Shared"):
                Shared_lines.append(line)
            elif line.startswith("Private"):
                Private_lines.append(line)
            elif line.startswith("Pss"):
                have_pss = 1
                Pss_lines.append(line)
        mem_id = digester.hexdigest()
        Shared = sum([int(line.split()[1]) for line in Shared_lines])
        Private = sum([int(line.split()[1]) for line in Private_lines])
        #Note Shared + Private = Rss above
        #The Rss in smaps includes video card mem etc.
        if have_pss:
            pss_adjust = 0.5 # add 0.5KiB as this avg error due to trunctation
            Pss = sum([float(line.split()[1])+pss_adjust for line in Pss_lines])
            Shared = Pss - Private
    elif (2,6,1) <= kernel_ver() <= (2,6,9):
        Shared = 0 #lots of overestimation, but what can we do?
        Private = Rss
    else:
        Shared = int(proc.open(pid, 'statm').readline().split()[2])
        Shared *= PAGESIZE
        Private = Rss - Shared
    return (Private, Shared, mem_id)


def getCmdName(pid, split_args):
    cmdline = proc.open(pid, 'cmdline').read().split("\0")
    if cmdline[-1] == '' and len(cmdline) > 1:
        cmdline = cmdline[:-1]

    path = proc.path(pid, 'exe')
    try:
        path = os.readlink(path)
        # Some symlink targets were seen to contain NULs on RHEL 5 at least
        # https://github.com/pixelb/scripts/pull/10, so take string up to NUL
        path = path.split('\0')[0]
    except OSError:
        val = sys.exc_info()[1]
        if (val.errno == errno.ENOENT or # either kernel thread or process gone
            val.errno == errno.EPERM):
            raise LookupError

    if split_args:
        return " ".join(cmdline)
    if path.endswith(" (deleted)"):
        path = path[:-10]
        if os.path.exists(path):
            path += " [updated]"
        else:
            if os.path.exists(cmdline[0]):
                path = cmdline[0] + " [updated]"
            else:
                path += " [deleted]"
    exe = os.path.basename(path)
    cmd = proc.open(pid, 'status').readline()[6:-1]
    if exe.startswith(cmd):
        cmd = exe #show non truncated version
        #Note because we show the non truncated name
        #one can have separated programs as follows:
        #584.0 KiB +   1.0 MiB =   1.6 MiB    mozilla-thunder (exe -> bash)
        # 56.0 MiB +  22.2 MiB =  78.2 MiB    mozilla-thunderbird-bin
    return cmd


#The following matches "du -h" output
#see also human.py
def human(num, power="Ki"):
    powers = ["Ki", "Mi", "Gi", "Ti"]
    while num >= 1000: #4 digits
        num /= 1024.0
        power = powers[powers.index(power)+1]
    return "%.1f %s" % (num, power)


def cmd_with_count(cmd, count):
    if count > 1:
        return "%s (%u)" % (cmd, count)
    else:
        return cmd

#Warn of possible inaccuracies
#2 = accurate & can total
#1 = accurate only considering each process in isolation
#0 = some shared mem not reported
#-1= all shared mem not reported
def shared_val_accuracy():
    """http://wiki.apache.org/spamassassin/TopSharedMemoryBug"""
    kv = kernel_ver()
    if kv[:2] == (2,4):
        if proc.open('meminfo').read().find("Inact_") == -1:
            return 1
        return 0
    elif kv[:2] == (2,6):
        pid = os.getpid()
        if os.path.exists(proc.path(pid, 'smaps')):
            if proc.open(pid, 'smaps').read().find("Pss:")!=-1:
                return 2
            else:
                return 1
        if (2,6,1) <= kv <= (2,6,9):
            return -1
        return 0
    elif kv[0] > 2:
        return 2
    else:
        return 1

def show_shared_val_accuracy( possible_inacc ):
    if possible_inacc == -1:
        sys.stderr.write(
         "Warning: Shared memory is not reported by this system.\n"
        )
        sys.stderr.write(
         "Values reported will be too large, and totals are not reported\n"
        )
    elif possible_inacc == 0:
        sys.stderr.write(
         "Warning: Shared memory is not reported accurately by this system.\n"
        )
        sys.stderr.write(
         "Values reported could be too large, and totals are not reported\n"
        )
    elif possible_inacc == 1:
        sys.stderr.write(
         "Warning: Shared memory is slightly over-estimated by this system\n"
         "for each program, so totals are not reported.\n"
        )
    sys.stderr.close()

def get_memory_usage( pids_to_show, split_args, include_self=False, only_self=False ):
    cmds = {}
    shareds = {}
    mem_ids = {}
    count = {}
    for pid in os.listdir(proc.path('')):
        if not pid.isdigit():
            continue
        pid = int(pid)

        # Some filters
        if only_self and pid != our_pid:
            continue
        if pid == our_pid and not include_self:
            continue
        if pids_to_show is not None and pid not in pids_to_show:
            continue

        try:
            cmd = getCmdName(pid, split_args)
        except LookupError:
            #permission denied or
            #kernel threads don't have exe links or
            #process gone
            continue

        try:
            private, shared, mem_id = getMemStats(pid)
        except RuntimeError:
            continue #process gone
        if shareds.get(cmd):
            if have_pss: #add shared portion of PSS together
                shareds[cmd] += shared
            elif shareds[cmd] < shared: #just take largest shared val
                shareds[cmd] = shared
        else:
            shareds[cmd] = shared
        cmds[cmd] = cmds.setdefault(cmd, 0) + private
        if cmd in count:
            count[cmd] += 1
        else:
            count[cmd] = 1
        mem_ids.setdefault(cmd, {}).update({mem_id:None})

    #Add shared mem for each program
    total = 0
    for cmd in cmds:
        cmd_count = count[cmd]
        if len(mem_ids[cmd]) == 1 and cmd_count > 1:
            # Assume this program is using CLONE_VM without CLONE_THREAD
            # so only account for one of the processes
            cmds[cmd] /= cmd_count
            if have_pss:
                shareds[cmd] /= cmd_count
        cmds[cmd] = cmds[cmd] + shareds[cmd]
        total += cmds[cmd] #valid if PSS available

    sorted_cmds = sorted(cmds.items(), key=lambda x:x[1])
    sorted_cmds = [x for x in sorted_cmds if x[1]]

    return sorted_cmds, shareds, count, total

def graph_setup():
    if not os.path.exists("mem-usage-graph"):
        os.makedirs("mem-usage-graph")

def graph_memory_usage(sorted_cmds, shareds, count, total):
    for cmd in sorted_cmds:
        filepath = "%s/%s" % ("mem-usage-graph", cmd[0])
        fp = open(filepath,"a+b")
        sys.stdout.write("%s\n" % (cmd[0]))
        fp.close()

def print_header():
    sys.stdout.write(" Private  +   Shared  =  RAM used\tProgram \n\n")

def print_memory_usage(sorted_cmds, shareds, count, total):
    return
    for cmd in sorted_cmds:
        sys.stdout.write("%8sB + %8sB = %8sB\t%s\n" %
                         (human(cmd[1] - shareds[cmd[0]]),
                          human(shareds[cmd[0]]), human(cmd[1]),
                          cmd_with_count(cmd[0], count[cmd[0]])))
    if have_pss:
        sys.stdout.write("%s\n%s%8sB\n%s\n" %
                         ("-" * 33, " " * 24, human(total), "=" * 33))

def verify_environment():
    if os.geteuid() != 0:
        sys.stderr.write("Sorry, root permission required.\n")
        if __name__ == '__main__':
            sys.stderr.close()
            sys.exit(1)

    try:
        kv = kernel_ver()
    except (IOError, OSError):
        val = sys.exc_info()[1]
        if val.errno == errno.ENOENT:
            sys.stderr.write(
              "Couldn't access " + proc.path('') + "\n"
              "Only GNU/Linux and FreeBSD (with linprocfs) are supported\n")
            sys.exit(2)
        else:
            raise

if __name__ == '__main__':
    verify_environment()
    split_args, pids_to_show, watch, graph = parse_options()

    print_header()
    ref_time = datetime.datetime.now()

    if watch is not None:
        try:
            sorted_cmds = True
            while sorted_cmds:
                sorted_cmds, shareds, count, total = get_memory_usage( pids_to_show, split_args )
                print_memory_usage(sorted_cmds, shareds, count, total)
                time.sleep(watch)
            else:
                sys.stdout.write('Process does not exist anymore.\n')
        except KeyboardInterrupt:
            if graph:
                sys.stdout.write('\nwriting data to mem-data, waiting\n')
                graph_setup()
                graph_memory_usage(sorted_cmds, shareds, count, total)
    else:
        # This is the default behavior
        sorted_cmds, shareds, count, total = get_memory_usage( pids_to_show, split_args )
        print_memory_usage(sorted_cmds, shareds, count, total)


    # We must close explicitly, so that any EPIPE exception
    # is handled by our excepthook, rather than the default
    # one which is reenabled after this script finishes.
    sys.stdout.close()

    vm_accuracy = shared_val_accuracy()
    show_shared_val_accuracy( vm_accuracy )

