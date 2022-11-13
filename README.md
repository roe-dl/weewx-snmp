# weewx-snmp
WeeWX service to fetch data by SNMP

## Configuration

Example configuration:
```
[DataBindings]

    # additional section for an extra database to store the SNMP data
    # optional!
    [[snmp_binding]]
        data_base = snmp_sqlite
        table_name = archive
        manager = weewx.manager.DaySummaryManager
        schema = user.snmp.schema

[Databases]

    # additional section for an extra database to store SNMP data
    # optional!
    [[snmp_sqlite]]
        database_name = snmp.sdb
        database_type = SQLite

# section in weewx.conf to add for the SNMP service
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

        # authentication data
        community = replace_me
        username = replace_me
        password = replace_me

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

* http://www.oidview.com/mibs/0/SNMPv2-MIB.html
* http://www.oidview.com/mibs/0/SNMPv2-SMI.html
* http://www.oidview.com/mibs/0/UPS-MIB.html
