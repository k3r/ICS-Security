

rule modbus_python {
    meta:
        author = "Nicolas CHARREL"
        version = "0.1"
        description = "That rule try to detect the use of modbus protocol in a python code."
    strings:
        $s1 = "pyModbusTCP"
        $s2 = "PyModbus"
        $s3 = "minimalmodbus"
        $s4 = "umodbus"
    condition:
        any of them
}
