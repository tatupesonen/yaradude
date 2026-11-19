/*
 * Example rules for yaradude development: benign document markers.
 */

// Matches PDF files that declare an embedded JavaScript action.
rule PDF_With_JavaScript : document pdf
{
    meta:
        description = "PDF document with a JavaScript action"
        author = "yaradude examples"
        date = "2026-11-19"
        score = 40
        reviewed = true
    strings:
        $header = "%PDF-"
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
    condition:
        $header at 0 and any of ($js*)
}

// Office Open XML container (docx, xlsx, pptx): a ZIP file with a
// [Content_Types].xml entry near the start.
rule OOXML_Container : document office
{
    meta:
        description = "Office Open XML document"
        author = "yaradude examples"
        min_size = 22
        offset_hint = -1
    strings:
        $zip = { 50 4B 03 04 }
        $content_types = "[Content_Types].xml" nocase
    condition:
        $zip at 0 and $content_types in (0..1024)
}

rule RTF_Document : document { meta: description = "Rich Text Format document" strings: $rtf = "{\\rtf1" condition: $rtf at 0 }
