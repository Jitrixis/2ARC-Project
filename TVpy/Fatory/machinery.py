__author__ = 'jitrixis'

from scapy.all import *
from forgery import *
from sniffery import *

class Engine:
    def __init__(self, device):
        self.__device = device
        self.__forgery = Forgery("a4:17:31:50:73:2b", "10.31.16.253")
        pass

    def sendICMP(self):
        p1 = self.__forgery.generateArpRequest("10.31.19.101")
        result = self.send_receive(p1)

        if result is None:
            return None

        p2 = self.__forgery.generateIcmpRequest(result["packet"]["arp"].getHwsrc(), "10.31.19.101")

        result = self.send_receive(p2)

        print result

    def send_receive(self, pkt, to=10):
        return raw_send_receive(conf.L2socket(iface=self.__device, filter=None, nofilter=0, type=ETH_P_ALL), Raw(pkt), timeout=to,  verbose=False)

'''OVERRIDE : sendrcv from scapy'''
def raw_send_receive(pks, pkt, timeout = None, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)

    if verbose is None:
        verbose = conf.verb
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0

        if timeout < 0:
            timeout = None

        rdpipe,wrpipe = os.pipe()
        rdpipe=os.fdopen(rdpipe)
        wrpipe=os.fdopen(wrpipe,"w")

        pid=1
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    sys.stdin.close()
                    rdpipe.close()
                    try:
                        i = 0
                        if verbose:
                            print "Begin emission:"
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print "Finished to send %i packets." % i
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error in child %i" % os.getpid())
                        log_runtime.info("--- Error in child %i" % os.getpid())
                finally:
                    try:
                        os.setpgrp() # Chance process group to avoid ctrl-C
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                        cPickle.dump( (conf.netcache,sent_times), wrpipe )
                        wrpipe.close()
                    except:
                        pass
            elif pid < 0:
                log_runtime.error("fork error")
            else:
                wrpipe.close()
                stoptime = 0
                remaintime = None
                inmask = [rdpipe,pks]
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = None
                            if arch.FREEBSD or arch.DARWIN:
                                inp, out, err = select(inmask,[],[], 0.05)
                                if len(inp) == 0 or pks in inp:
                                    r = pks.nonblock_recv()
                            else:
                                inp, out, err = select(inmask,[],[], remaintime)
                                if len(inp) == 0:
                                    break
                                if pks in inp:
                                    r = pks.recv(MTU)
                            if rdpipe in inp:
                                if timeout:
                                    stoptime = time.time()+timeout
                                del(inmask[inmask.index(rdpipe)])
                            if r is None:
                                continue
                            '''OVERRIDE'''
                            harvest = Harvest()
                            if harvest.check(pkt, r):
                                return Sniffery().sniff(str(r))
                            '''OVERRIDE'''
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i in range(len(hlst)):
                                    if r.answers(hlst[i]):
                                        ans.append((hlst[i],r))
                                        if verbose > 1:
                                            os.write(1, "*")
                                        ok = 1
                                        if not multi:
                                            del(hlst[i])
                                            notans -= 1;
                                        else:
                                            if not hasattr(hlst[i], '_answered'):
                                                notans -= 1;
                                            hlst[i]._answered = 1;
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, ".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    try:
                        nc,sent_times = cPickle.load(rdpipe)
                    except EOFError:
                        warning("Child died unexpectedly. Packets may have not been sent %i"%os.getpid())
                    else:
                        conf.netcache.update(nc)
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
                    os.waitpid(pid,0)
        finally:
            if pid == 0:
                os._exit(0)

        remain = reduce(list.__add__, hsent.values(), [])
        if multi:
            remain = filter(lambda p: not hasattr(p, '_answered'), remain);

        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop

        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1

    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)

    if verbose:
        print "\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans)
    '''OVERRIDE'''
    return None