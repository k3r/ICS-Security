
rule opc_python {
    meta:
        author = "Nicolas CHARREL"
        version = "0.1"
        description = "That rule try to detect the use of OPC protocol in a python code."
    strings:
        $s1 = "opcua"
    condition:
        any of them
}
