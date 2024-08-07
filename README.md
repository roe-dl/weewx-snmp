# weewx-snmp
WeeWX service to fetch data by SNMP

There are sensors that offer their readings by SNMP. Fortunately there
is a powerful Python module available to speak SNMP. This extension
makes it available to WeeWX.

## Prerequisites

Install PySNMP if it is not already there.

```
sudo apt-get install python3-pysnmp
```

In newer releases of Ubuntu you have to enter:

```
sudo apt-get install python3-pysnmp4
```


## Installation instructions

1) download

   ```
   wget -O weewx-snmp.zip https://github.com/roe-dl/weewx-snmp/archive/master.zip
   ```

2) run the installer

   WeeWX up to version 4.X

   ```
   sudo wee_extension --install weewx-snmp.zip
   ```

   WeeWX from version 5.0 on and WeeWX packet installation

   ```
   sudo weectl extension install weewx-snmp.zip
   ```

   WeeWX from version 5.0 on and WeeWX pip installation into an virtual environment

   ```shell
   source ~/weewx-venv/bin/activate
   weectl extension install weewx-snmp.zip
   ```
   
3) edit configuration in weewx.conf

   Before using this extension you have to set up which devices
   to be queried and which variables to be fetched. See
   section "Configuration" for details.

   **Caution!** If you want to save the readings to a separate 
   database and have it created properly, you have to edit
   the configuration file before you **first** start WeeWX
   after installing the extension. 

   If you want to add additional variables afterwards you have to 
   extend the database schema manually by using the
   `wee_database` utility (`weectl database` in WeeWX 5).
   This is **not** done automatically.

5) restart weewx

   for SysVinit systems:

   ```
   sudo /etc/init.d/weewx stop
   sudo /etc/init.d/weewx start
   ```

   for systemd systems:

   ```
   sudo systemctl stop weewx
   sudo systemctl start weewx
   ```

## Configuration

This extension can query several devices simultaneously. It creates a
separate thread for each of them. In section `[SNMP]` of `weewx.conf` 
each device has its own subsection. You can name that subsection as
you want. The name is used to name the thread, only. 

Each subsection contains of the following information:
* connection data
* authentication data
* subsubsection(s) containing the description of the variables 
  (observation types) to fetch, their names in WeeWX,
  unit and unit group, and - if necessary - some conversion
  formula.

### General options

* `enable`: If True or omitted, retrieve data from that device.
  If False, that subsection is not used. (optional)
* `log_success`: If True, log successful operation. 
  If omitted, global options apply. (optional)
* `log_failure`: If True, log unsuccessful operation. 
  If omitted, global options apply. (optional)
* `data_binding`: data binding to use for storage 
  (or `None` if no extra data binding is to be used)
* `include`: include configuration data from the file indicated by this
  option into the `[SNMP]` section. Use absolute path. This is to
  increase readability of the configuration only. It is up to you to
  decide wether to put the configuration data directly into `weewx.conf` 
  or into the include file.

### Connection configuration

* `host`: host name or IP address of the device to get data from
  (mandatory)
* `port`: port number (mandatory, standard 161)
* `timeout`: request timeout (optional, default is 0.5s)
* `retries`: request retries (0 is no retries) (optional, default is
   no retries)
* `query_interval`: query interval (optional, default 5s)

### Authentication configuration

There are different authentication methods for SNMP version 1 and 2c
on one hand and 3 on the other hand.

configuration entries for SNMP version 1 and 2c:
* `protocol_version`: Protocol version to use. Possible values are 1 or 2c
* `community`: Community name for receiving data. Often it is `public`.

configuration entries for SNMP version 3:
* `protocol_version`: Protocol version to use. In this case 3.
* `username`: User name
* `password`: Password (optional)
* `password_protocol`: Authentication protocol, see below
  for possible values (optional)
* `encryption`: Encryption passphrase (optional)
* `encryption_protocol`: Privacy protocol (means: encryption protocol),
  see below for possible values (optional)

Possible values for `password_protocol`:
* usmNoAuthProtocol
* usmHMACMD5AuthProtocol
* usmHMACSHAAuthProtocol
* usmHMAC128SHA224AuthProtocol
* usmHMAC192SHA256AuthProtocol
* usmHMAC256SHA384AuthProtocol
* usmHMAC384SHA512AuthProtocol

Possible values for `encryption_protocol`:
* usmNoPrivProtocol
* usmDESPrivProtocol
* usm3DESEDEPrivProtocol
* usmAesCfb128Protocol
* usmAesCfb192Protocol
* usmAesCfb256Protocol
* usmAesBlumenthalCfb192Protocol
* usmAesBlumenthalCfb256Protocol

### Variables configuration

There are two possible subsubsections, `[[[once]]]` and `[[[loop]]]`,
the former is used once at program start and logged to syslog, 
the latter is performed continuously and included in the LOOP 
packets. If no `[[[once]]]` subsubsection is present, defaults
are used, fetching some general device information. For the
`[[[loop]]]` subsubsection, there are no defaults.

* `oid`: OID of the variable. If omitted, the section name is used 
  for OID.
* `conversion`: optional conversion formula
* `name`: Observation type name used inside WeeWX
* `unit`: The unit the reading is provided by the device.
  That is **not** the unit the readings are to be saved to
  database or displayed in skins. For those purposes the values are converted
  automatically by WeeWX. The unit here is the source unit.
* `group`: Unit group, used by WeeWX to choose the right unit
  to save to database and to display in skins.
  If omitted, the extension tries to determine the unit group
  by the unit. 
* `sql_datatype`: If specified, this datatype is used when creating
  the database table. Default is `REAL` if omitted. This entry can
  be used for string data especially. An example for a string datatype
  is `VARCHAR(30)`.

See [WeeWX Customization Guide](http://www.weewx.com/docs/customizing.htm#units)
for a list of predefined units and unit groups.

The observation types are automatically registered with WeeWX.

The standardized OID for sensor readings is `iso.3.6.1.2.1.99.1.1.1.4`,
followed by an index of the sensor, starting with `.1`.

### Accumulators

Accumulators define how to aggregate the readings during the
archive interval.
This extension tries to set up reasonable accumulators for the
observation types defined in the `[[[loop]]]` subsubsection. If
they do not work for you, you can set up accumulators manually
in the `[Accumulator]` section of `weewx.conf`.
See [WeeWX Accumulators wiki page](https://github.com/weewx/weewx/wiki/Accumulators)
for how to set up accumulators in WeeWX.

The accumulator `firstlast` does not work for numeric values of this
extension. The reason is that the database schema within this extension
includes all numeric values in the list of daily summeries tables. But
WeeWX let you have an observation type either with a daily summeries
table or the `firstlast` accumulator, not both.

### Example configuration

```
...

[DataBindings]
    ...
    # additional section for an extra database to store the SNMP data
    # optional!
    [[snmp_binding]]
        database = snmp_sqlite
        table_name = archive
        manager = weewx.manager.DaySummaryManager
        schema = user.snmp.schema

[Databases]
    ...
    # additional section for an extra database to store SNMP data
    # optional!
    [[snmp_sqlite]]
        database_name = snmp.sdb
        database_type = SQLite

[Engine]
    [[Services]]
        data_services = ..., user.snmp.SNMPservice
        archive_services = ..., user.snmp.SNMParchive

...

[SNMP]

    # extra database
    # optional!
    # to switch off set data_binding = None
    data_binding = snmp_binding

    # Each subsection represents one device to be connected. There
    # can be several such sections. The section name can be freely 
    # chosen. It is only used for the thread name. 
    [[UPS]]

        # host and port to be connected
        host = replace_me
        port = 161
        # optional
        #query_interval = 5

        # authentication data
        protocol_version = 2c # possible values '1', '2c', '3'
        # for version 1 and 2c
        community = replace_me
        # for version 3
        #username = replace_me
        #password = replace_me
        #password_protocol = usmNoAuthProtocol

        # data to fetch
        [[[loop]]]
            # UPS data
            [[[[iso.3.6.1.2.1.33.1.3.3.1.2.1]]]]
                name = 'upsInputFrequency'
                conversion = lambda x:float(x)/10.0
                unit = 'hertz'
                group = 'group_frequency'
            [[[[iso.3.6.1.2.1.33.1.3.3.1.3.1]]]]
                name = 'upsInputVoltage'
                unit = 'volt'
                group = 'group_volt'
            [[[[iso.3.6.1.2.1.33.1.4.1.0]]]]
                name = 'upsOutputSource'
            [[[[iso.3.6.1.2.1.33.1.4.2.0]]]]
                name = 'upsOutputFrequency'
                conversion = lambda x:float(x)/10.0
                unit = 'hertz'
                group = 'group_frequency'
            [[[[iso.3.6.1.2.1.33.1.4.4.1.2.1]]]]
                name = 'upsOutputVoltage'
                conversion = lambda x:float(x)
                unit = 'volt'
                group = 'group_volt'
            [[[[iso.3.6.1.2.1.33.1.4.4.1.3.1]]]]
                name = 'upsOutputCurrent'
                conversion = lambda x:float(x)/10.0
                unit = 'amp'
                group = 'group_amp'
            [[[[iso.3.6.1.2.1.33.1.4.4.1.4.1]]]]
                name = 'upsOutputPower'
                conversion = None
                unit = 'watt'
                group ='group_power'
            [[[[iso.3.6.1.2.1.33.1.4.4.1.5.1]]]]
                name = 'upsOutputPercentLoad'
                unit = 'percent'
                group = 'group_percent'
            # extra sensor data
            [[[[iso.3.6.1.2.1.99.1.1.1.4.1]]]]
                # cabinet temperature
                name = 'cabTemp'
                conversion = lambda x: float(x)/10.0
                unit = 'degree_C'
                group = 'group_temperature'
            [[[[iso.3.6.1.2.1.99.1.1.1.4.2]]]]
                # cabinet humidity
                name = 'cabHumidity'
                unit = 'percent'
                group = 'group_percent'
```

### Default `[[[once]]]` section

This is the default `[[[once]]]` subsubsection that applies if no `[[[once]]]`
subsubsection is present. 

```
        [[[once]]]
            [[[[SNMPv2-MIB::sysDescr.0]]]]
                oid = 'SNMPv2-MIB', 'sysDescr', 0
                name = sysDescr
            [[[[SNMPv2-MIB::sysObjectID.0]]]]
                oid = 'SNMPv2-MIB', 'sysObjectID', 0
                name = sysObjectID
            [[[[SNMPv2-MIB::sysUpTime.0]]]]
                oid = 'SNMPv2-MIB', 'sysUpTime', 0
                name = sysUpTime
            [[[[SNMPv2-MIB::sysContact.0]]]]
                oid = 'SNMPv2-MIB', 'sysContact', 0
                name = sysContact
            [[[[SNMPv2-MIB::sysName.0]]]]
                oid = 'SNMPv2-MIB', 'sysName', 0
                name = sysName
            [[[[SNMPv2-MIB::sysLocation.0]]]]
                oid = 'SNMPv2-MIB', 'sysLocation', 0
                name = sysLocation
            [[[[SNMPv2-MIB::sysServices.0]]]]
                oid = 'SNMPv2-MIB', 'sysServices', 0
                name = sysServices
            [[[[SNMPv2-MIB::sysORLastChange.0]]]]
                oid = 'SNMPv2-MIB', 'sysORLastChange', 0
                name = sysORLastChange
```

## OIDs

See [OIDs wiki page](https://github.com/roe-dl/weewx-snmp/wiki/OIDs)

## References

### SNMP

* [Net-SNMP tools](http://www.net-snmp.org) 
  (contains `snmpget` and `snmpwalk` command line tool to retrieve
  data from SNMP agents)
* [SNMP tester for Windows](https://www.heise.de/download/product/paessler-snmp-tester-29883)

### Python modules

* [PySNMP documentation](https://pysnmp.readthedocs.io/en/latest/)
* [PySNMP at Github](https://github.com/pysnmp/pysnmp)
* [PyASN1 at Github](https://github.com/pysnmp/pyasn1)
* [PySMI at Github](https://github.com/pysnmp/pysmi)

### MIBs

* http://www.oidview.com/mibs/0/SNMPv2-MIB.html
* http://www.oidview.com/mibs/0/SNMPv2-SMI.html
* http://www.oidview.com/mibs/0/UPS-MIB.html
* https://www.circitor.fr/Mibs/Html/R/RFC1213-MIB.php
* https://www.circitor.fr/Mibs/Html/E/ENTITY-SENSOR-MIB.php
* [Private enterprise numbers](https://www.iana.org/assignments/enterprise-numbers/)

### WeeWX

* [WeeWX website](https://www.weewx.com)
* [WeeWX information in german](https://www.woellsdorf-wetter.de/software/weewx.html)
* [WeeWX customization guide](https://www.weewx.com/docs/customizing.htm)
  (See this guide for using the observation types in skins.)
* [WeeWX accumulators](https://github.com/weewx/weewx/wiki/Accumulators)
  (This extension tries to set up reasonable accumulators for the
  observation types, but if you want them different or if they do not
  work appropriately, you can define them in `weewx.conf`)
* [Calculation in templates](https://github.com/weewx/weewx/wiki/calculate-in-templates)
* [WeeWX extension to monitor the computer WeeWX is running on](https://github.com/matthewwall/weewx-cmon)
  (That is not related to SNMP, but to monitoring. It uses Linux tools.)
