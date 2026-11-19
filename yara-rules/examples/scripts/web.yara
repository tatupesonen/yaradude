// Example rules for scripts and web content. The regular expressions below
// contain braces, quotes, escaped slashes and "//" to exercise the splitter.

global rule Not_Too_Large { condition: filesize < 10MB }

rule Remote_Script_Include : web html
{
    meta:
        description = "HTML page that loads a script over plain http://"
        author = "yaradude examples"
    strings:
        $tag = /<script[^>]{0,64}src="http:\/\/[a-z0-9.\-]{1,64}\/[^"]{0,128}"/ nocase
    condition:
        $tag
}

rule Shell_Script : script { strings: $shebang = /^#!\/(usr\/)?bin\/(ba|z)?sh/ condition: $shebang at 0 } rule Python_Script : script { strings: $shebang = "#!/usr/bin/env python" condition: $shebang at 0 }

rule Powershell_Encoded_Command : script
{
    meta:
        description = "PowerShell started with an encoded command"
        author = "yaradude examples"
        note = "matches \"-enc\" and \"-EncodedCommand\""
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
    condition:
        $ps and $enc
}
