/* Conservative examples only. Matches are clues, not proof of malicious behavior. */
rule SecQuery_Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download string often seen in droppers; benign admin scripts may match"
        severity = "medium"
    strings:
        $a = "DownloadString" nocase ascii wide
        $b = "powershell" nocase ascii wide
    condition:
        $a and $b
}

rule SecQuery_EICAR_Test_File
{
    meta:
        description = "Standard antivirus test pattern; not malware"
        severity = "medium"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide
    condition:
        $eicar
}
