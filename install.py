# installer SNMP
# Copyright 2022 Johanna Roedenbeck
# Distributed under the terms of the GNU Public License (GPLv3)

from weecfg.extension import ExtensionInstaller

def loader():
    return SNMPInstaller()

class SNMPInstaller(ExtensionInstaller):
    def __init__(self):
        super(SNMPInstaller, self).__init__(
            version="0.1",
            name='SNMP',
            description='fetch data by SNMP',
            author="Johanna Roedenbeck",
            author_email="",
            data_services='user.snmp.SNMPservice',
            config={
              'DataBindings':{
                  'snmp_binding':{
                      'data_base':'snmp_sqlite',
                      'table_name':'archive',
                      'manager':'weewx.manager.DaySummaryManager',
                      'schema':'user.snmp.schema'}},
              'Databases':{
                  'snmp_sqlite':{
                      'database_name':'snmp.sdb',
                      'database_type':'SQLite'}},
              'SNMP':{
                  'data_binding':'snmp_binding'}
              }
            files=[('bin/user', ['bin/user/snmp.py'])]
            )
