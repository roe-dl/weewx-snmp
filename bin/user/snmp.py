#!/usr/bin/python3
# SNMP Service for WeeWX
# Copyright (C) 2022 Johanna Roedenbeck

"""

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""

VERSION = "0.1"

"""
    common units and unit groups:
  
    observation type    unit       unit group
    ------------------------------------------
    voltage             volt       group_volt
    current             amp        group_amp
    power               watt       group_power
    energy              watt_hour  group_energy
    percentage          percent    group_percent
  
    references:
    * http://www.oidview.com/mibs/0/SNMPv2-MIB.html
    * https://computer2know.de/monitoring-riello-usv-with-netman-204-adapter-using-snmp-:::657.html
    
"""

from pysnmp.hlapi import *
from pyasn1.error import *
from pysnmp.error import *
import threading 
import configobj
import time
import copy

# deal with differences between python 2 and python 3
try:
    # Python 3
    import queue
except ImportError:
    # Python 2
    # noinspection PyUnresolvedReferences
    import Queue as queue

if __name__ == '__main__':

    sys.path.append('/usr/share/weewx')
    
    def logdbg(x):
        print('DEBUG',x)
    def loginf(x):
        print('INFO',x)
    def logerr(x):
        print('ERROR',x)

else:

    try:
        # Test for new-style weewx logging by trying to import weeutil.logger
        import weeutil.logger
        import logging
        log = logging.getLogger("user.SNMP")

        def logdbg(msg):
            log.debug(msg)

        def loginf(msg):
            log.info(msg)

        def logerr(msg):
            log.error(msg)

    except ImportError:
        # Old-style weewx logging
        import syslog

        def logmsg(level, msg):
            syslog.syslog(level, 'user.SNMP: %s' % msg)

        def logdbg(msg):
            logmsg(syslog.LOG_DEBUG, msg)

        def loginf(msg):
            logmsg(syslog.LOG_INFO, msg)

        def logerr(msg):
            logmsg(syslog.LOG_ERR, msg)

import weewx
from weewx.engine import StdService
import weeutil.weeutil
        
SYSOBS = [{'oid':('SNMPv2-MIB', 'sysDescr', 0),'name':'sysDescr'},
        {'oid':('SNMPv2-MIB', 'sysObjectID', 0),'name':'sysObjectID'},
        {'oid':('SNMPv2-MIB', 'sysUpTime', 0),'name':'sysUpTime',},
        {'oid':('SNMPv2-MIB', 'sysContact', 0),'name':'sysContact'},
        {'oid':('SNMPv2-MIB', 'sysName', 0),'name':'sysName'},
        {'oid':('SNMPv2-MIB', 'sysLocation', 0),'name':'sysLocation'},
        {'oid':('SNMPv2-MIB', 'sysServices', 0),'name':'sysServices'},
        {'oid':('SNMPv2-MIB', 'sysORLastChange', 0),'name':'sysORLastChange'}]

##############################################################################
#    Database schema                                                         #
##############################################################################

exclude_from_summary = ['dateTime', 'usUnits', 'interval']

table = [('dateTime',             'INTEGER NOT NULL UNIQUE PRIMARY KEY'),
         ('usUnits',              'INTEGER NOT NULL'),
         ('interval',             'INTEGER NOT NULL')] 

def day_summaries():
    return [(e[0], 'scalar') for e in table
                 if e[0] not in exclude_from_summary and e[1]=='REAL'] 

schema = {
    'table': table,
    'day_summaries' : day_summaries()
}

##############################################################################

# PyAsn1Error
# PySnmpError
 
def _getoi(x):
    if isinstance(x['oid'],str):
        return (x['oid'],)
    else:
        return x['oid']

def printObjectTypeList(ot):
    for x in ot:
        # ObjectType
        print(x.__class__.__name__)
        print('str(x)           :',str(x))
        print('repr(x)          :',repr(x))
        print('x[0]             :',x[0])
        print('x[1]             :',x[1])
        # ObjectIdentity
        print(x[0].__class__.__name__)
        print('prettyPrint()    :',x[0].prettyPrint())
        print('isFullyResolved():',x[0].isFullyResolved())
        print('getMibSymbol()   :',x[0].getMibSymbol())
        print('getOid()         :',x[0].getOid())
        print('getLabel()       :',x[0].getLabel())
        print('getMibNode()     :',x[0].getMibNode())
        print()

class SNMPthread(threading.Thread):

    def __init__(self, name, conf_dict, data_queue, query_interval):
    
        super(SNMPthread,self).__init__(name='SNMP-'+name)

        self.data_queue = data_queue
        self.query_interval = query_interval
        
        self.running = True
        
        ots = ('once','loop')
        
        self.conf_dict = dict()
        # interpret configuration
        for ii in conf_dict:
            if ii in ots:
                # variables to read
                self.conf_dict[ii] = []
                for idx in conf_dict[ii]:
                    val = conf_dict[ii][idx]
                    x = dict()
                    x['oid'] = val['oid'] if 'oid' in val else idx
                    for jj in val:
                        vv = val[jj]
                        if vv in ('None','none'):
                            vv = None
                        elif jj=='conversion':
                            vv = eval(vv)
                        x[jj] = vv
                    self.conf_dict[ii].append(x)
            else:
                # general configuration values
                val = conf_dict[ii]
                if val in ('None','none'): 
                    val = None
                elif val in ('False','Off','No'):
                    val = False
                elif val in ('True','On','Yes'):
                    val = True
                elif ii=='port':
                    val = int(val)
                self.conf_dict[ii] = val
        # if no 'once' section defined use defaults
        if 'once' not in self.conf_dict: 
            self.conf_dict['once'] = copy.deepcopy(SYSOBS)
            for idx,val in enumerate(self.conf_dict['once']):
                self.conf_dict['once'][idx]['name'] = name + val['name']
        
        self.ot = dict()
        for ii in ots:
            self.ot[ii] = [ObjectType(ObjectIdentity(*_getoi(x))) for x in self.conf_dict[ii]]

    def shutDown(self):
        self.running = False
        loginf("thread '%s': shutdown requested" % self.name)
        
    def getRecord(self, ot):
    
        if __name__ == '__main__':
            print()
            print('-----',self.name,'-----',ot,'-----')

        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((self.conf_dict['host'], self.conf_dict['port'])),
            ContextData(),
            *self.ot[ot]
        )
        
        record = dict()

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            logerr(errorIndication)

        elif errorStatus:
            logerr('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

        else:
            for varBind in varBinds:
                #print(' = '.join([x.prettyPrint() for x in varBind]))
                #print(str(varBind[0]))
                #print(varBind[0].__class__.__name__)
                #print(varBind[1].__class__.__name__)
                try:
                    oid = varBind[0].getOid()
                    tp = varBind[1].__class__.__name__
                    for ii,val in enumerate(self.ot[ot]):
                        if oid==val[0].getOid():
                            val = varBind[1]
                            conf = self.conf_dict[ot][ii]
                            if tp=='DisplayString':
                                val = weewx.units.ValueTuple(val.prettyPrint(),None,None)
                            elif tp in ('Integer','Integer32','Integer64'):
                                val = int(val)
                                if 'conversion' in conf and conf['conversion'] is not None:
                                    val = conf['conversion'](val)
                                unit = conf['unit'] if 'unit' in conf else ''
                                group = conf['group'] if 'group' in conf else ''
                                val = weewx.units.ValueTuple(val,unit,group)
                            elif tp=='TimeStamp':
                                val = val.prettyPrint()
                            elif tp=='TimeTicks':
                                val = weewx.units.ValueTuple(int(val),'second','group_deltatime')
                            else:
                                val = weewx.units.ValueTuple(val.prettyPrint(),None,None)
                            record[conf['name']] = val
                            if ot=='once':
                                val = varBind[1].prettyPrint()
                                if tp=='DisplayString':
                                    val = '"%s"' % val
                                loginf("%s = %s : %s" % (
                                  varBind[0].prettyPrint(),
                                  tp,val))
                            break
                    if __name__ == '__main__' and ot!='once':
                        val = varBind[1].prettyPrint()
                        if tp=='DisplayString': val = val.encode('iso-8859-1').decode('utf-8')
                        print(ii,varBind[0].prettyPrint(),' = ',tp,' : ',val)
                except (ArithmeticError,TypeError,LookupError,PyAsn1Error,PySnmpError) as e:
                    logerr("%s: %s" % (varBind[0].prettyPrint(),e))

        del iterator
        
        if ot!='once':
            self.put_data(record)

        
    def put_data(self, x):
        if x:
            if self.data_queue:
                try:
                    self.data_queue.put((self.name,x),
                                block=False)
                except queue.Full:
                    # If the queue is full (which should not happen),
                    # ignore the packet
                    pass
                except (KeyError,ValueError,LookupError,ArithmeticError) as e:
                    logerr("thread '%s': %s" % (self.name,e))

    def run(self):
        loginf("thread '%s' starting" % self.name)
        try:
            self.getRecord('once')
            while self.running:
                self.getRecord('loop')
                time.sleep(5)
        except Exception as e:
            logerr("thread '%s': %s" % (self.name,e))
        finally:
            loginf("thread '%s' stopped" % self.name)


class SNMPservice(StdService):

    def __init__(self, engine, config_dict):
        super(SNMPservice,self).__init__(engine, config_dict)
        loginf("SNMP %s service" % VERSION)
        self.log_success = config_dict.get('log_success',True)
        self.log_failure = config_dict.get('log_failure',True)
        self.debug = weeutil.weeutil.to_int(config_dict.get('debug',0))
        if self.debug>0:
            self.log_success = True
            self.log_failure = True
        self.threads = dict()
        self.dbm = None
        if 'SNMP' in config_dict:
            ct = 0
            for name in config_dict['SNMP'].sections:
                if config_dict['SNMP'][name].get('enable',
                        config_dict['SNMP'].get('enable',True)):
                    if self._create_thread(name,
                            config_dict['SNMP'][name]):
                        ct += 1
            if ct>0 and __name__!='__main__':
                self.bind(weewx.NEW_LOOP_PACKET, self.new_loop_packet)
                self.bind(weewx.NEW_ARCHIVE_RECORD, self.new_archive_record)
            # init schema
            schema = {
                'table':table,
                'day_summaries':day_summaries()}
            if __name__=='__main__':
                print('----------')
                print(schema)
                print('----------')
            # init database
            binding = config_dict['SNMP'].get('data_binding','snmp_binding')
            if binding in ('None','none'): binding = None
            if binding:
                binding_found = 'DataBindings' in config_dict.sections and binding in config_dict['DataBindings']
            else:
                binding_found = None
            self.dbm_init(engine,binding,binding_found)

    def _create_thread(self, thread_name, thread_dict):
        host = thread_dict.get('host')
        query_interval = thread_dict.get('query_interval',1)
        # IP address is mandatory.
        if not host:
            logerr("thread '%s': missing IP address" % thread_name) 
            return False
        loginf("thread %s, host %s, poll interval %s" % (thread_name,host,query_interval))
        # create thread
        self.threads[thread_name] = dict()
        self.threads[thread_name]['queue'] = queue.Queue()
        self.threads[thread_name]['thread'] = SNMPthread(thread_name,thread_dict,self.threads[thread_name]['queue'],query_interval)
        # initialize observation types
        for ii in thread_dict['loop']:
            obstype = thread_dict['loop'][ii].get('name')
            obsunit = thread_dict['loop'][ii].get('unit')
            obsgroup = thread_dict['loop'][ii].get('group')
            obsdatatype = 'REAL'
            if not obsgroup and obsunit:
                # if no unit group is given, try to find out
                for jj in weewx.units.MetricUnits:
                    if weewx.units.MetricUnits[jj]==obsunit:
                        obsgroup = jj
                        break
                if not obsgroup:
                    for jj in weewx.units.USUnits:
                        if weewx.units.USUnits[jj]==obsunit:
                            obsgroup = jj
                            break
            if obstype and obsgroup:
                weewx.units.obs_group_dict.setdefault(obstype,obsgroup)
                table.append((obstype,obsdatatype))
        # start thread
        self.threads[thread_name]['thread'].start()
        return True
        
    def shutDown(self):
        """ shutdown threads and close database """
        for ii in self.threads:
            try:
                self.threads[ii]['thread'].shutDown()
            except Exception:
                pass
        try:
            self.dbm_close()
        except Exception:
            pass
        
    def _process_data(self, thread_name):
        # get collected data
        data = None
        while True:
            try:
                data1 = self.threads[thread_name]['queue'].get(block=False)
            except queue.Empty:
                break
            else:
                data = data1
        if data:
            return data[1]
        return None

    def new_loop_packet(self, event):
        for thread_name in self.threads:
            reply = self._process_data(thread_name)
            if reply:
                data = self._to_weewx(thread_name,reply,event.packet['usUnits'])
                # 'dateTime' and 'interval' must not be in data
                if 'dateTime' in data: del data['dateTime']
                if 'interval' in data: del data['interval']
                # log 
                if self.debug>=3: 
                    logdbg("PACKET %s:%s" % (thread_name,data))
                # update loop packet with device data
                event.packet.update(data)
                if self.dbm:
                    self.dbm_new_loop_packet(event.packet)

    def new_archive_record(self, event):
        if self.dbm:
            self.dbm_new_archive_record(event.record)

    def _to_weewx(self, thread_name, reply, usUnits):
        data = dict()
        for key in reply:
            #print('*',key)
            if key in ('time','interval','count','sysStatus'):
                pass
            elif key in ('interval','count','sysStatus'):
                data[key] = reply[key]
            else:
                try:
                    val = reply[key]
                    val = weewx.units.convertStd(val, usUnits)[0]
                except (TypeError,ValueError,LookupError,ArithmeticError) as e:
                    try:
                        val = reply[key][0]
                    except LookupError:
                        val = None
                data[key] = val
        return data

    def dbm_init(self, engine, binding, binding_found):
        self.accumulator = None
        self.old_accumulator = None
        self.dbm = None
        if not binding: 
            loginf("no database storage configured")
            return
        if not binding_found: 
            logerr("binding '%s' not found in weewx.conf" % binding)
            return
        self.dbm = engine.db_binder.get_manager(data_binding=binding,
                                                     initialize=True)
        if self.dbm:
            loginf("Using binding '%s' to database '%s'" % (binding,self.dbm.database_name))
            # Back fill the daily summaries.
            _nrecs, _ndays = self.dbm.backfill_day_summary()
        else:
            loginf("no database access")
    
    def dbm_close(self):
        if self.dbm:
            self.dbm.close()
        
    def dbm_new_loop_packet(self, packet):
        """ Copyright (C) Tom Keffer """
        # Do we have an accumulator at all? If not, create one:
        if not self.accumulator:
            self.accumulator = self._new_accumulator(packet['dateTime'])

        # Try adding the LOOP packet to the existing accumulator. If the
        # timestamp is outside the timespan of the accumulator, an exception
        # will be thrown:
        try:
            self.accumulator.addRecord(packet, add_hilo=True)
        except weewx.accum.OutOfSpan:
            # Shuffle accumulators:
            (self.old_accumulator, self.accumulator) = \
                (self.accumulator, self._new_accumulator(packet['dateTime']))
            # Try again:
            self.accumulator.addRecord(packet, add_hilo=True)
        
    def dbm_new_archive_record(self, record):
        if self.dbm:
            self.dbm.addRecord(record,
                           accumulator=self.old_accumulator,
                           log_success=self.log_success,
                           log_failure=self.log_failure)
        
    def _new_accumulator(self, timestamp):
        """ Copyright (C) Tom Keffer """
        start_ts = weeutil.weeutil.startOfInterval(timestamp,
                                                   self.archive_interval)
        end_ts = start_ts + self.archive_interval

        # Instantiate a new accumulator
        new_accumulator = weewx.accum.Accum(weeutil.weeutil.TimeSpan(start_ts, end_ts))
        return new_accumulator

        
if __name__ == '__main__':

    conf_dict = configobj.ConfigObj("SNMP.conf")

    if False:
    
        q = queue.Queue()
        t = SNMPthread('UPS',conf_dict['SNMP']['UPS'],q)
        t.start()

        try:
            while True:
                x = q.get(block=True)
                print(x)
        except (Exception,KeyboardInterrupt):
            pass

        print('xxxxxxxxxxxxx')
        t.shutDown()
        print('+++++++++++++')
        
    else:
    
        sv = SNMPservice(None,conf_dict)
        
        try:
            while True:
                event = weewx.Event(weewx.NEW_LOOP_PACKET)
                event.packet = {'usUnits':weewx.METRIC}
                sv.new_loop_packet(event)
                if len(event.packet)>1:
                    print(event.packet)
        except Exception as e:
            print('**MAIN**',e)
        except KeyboardInterrupt:
            print()
            print('**MAIN** CTRL-C pressed')
            
        sv.shutDown()

    #printObjectTypeList(ot)    
    