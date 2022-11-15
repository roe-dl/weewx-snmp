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

## Installation instructions

1) download

   ```
   wget -O weewx-snmp.zip https://github.com/roe-dl/weewx-snmp/archive/master.zip
   ```

2) run the installer

   ```
   sudo wee_extension --install weewx-snmp.zip
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
   `wee_database` utility. This is **not** done automatically.

5) restart weewx

   ```
   sudo /etc/init.d/weewx stop
   sudo /etc/init.d/weewx start
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

### Connection configuration

* `host`: host name or IP address of the device to get data from
  (mandatory)
* `port`: port number (mandatory, standard 161)
* `query_interval`: query interval (optional, default 5s)

### Authentication configuration

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

There are two possible subsubsections, `[[once]]` and `[[loop]]`,
the former is used once at program start and logged to syslog, 
the latter is performed continuously and included in the LOOP 
packets. If no `[[once]]` subsubsection is present, defaults
are used, fetching some general device information. For the
`[[loop]]` subsubsection, there are no defaults.

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

The observation types are automatically registered with WeeWX.

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

## References

* [SNMP Documentation](https://pysnmp.readthedocs.io/en/latest/)
* http://www.oidview.com/mibs/0/SNMPv2-MIB.html
* http://www.oidview.com/mibs/0/SNMPv2-SMI.html
* http://www.oidview.com/mibs/0/UPS-MIB.html
* [PySNMP at Github](https://github.com/etingof/pysnmp)
* [PyASN1 at Github](https://github.com/etingof/pyasn1)
* [PySMI at Github](https://github.com/etingof/pysmi)
