import itertools
import struct


def MUTATOR_PERMUTE_ALL(original_data, keep_orginal_size=False):
    """Shuffle all bytes at specific offset, and iterate over the permutations."""
    for perm in itertools.permutations(original_data):
        perm_b = b"".join( [ x for x in perm ] )
        yield( perm_b  )


def MUTATOR_FORMAT_STRING(original_data, keep_orginal_size=False):
    """Insert format strings."""
    values = [
        b'%s'*400,
        b'%p'*400,
        ]

    for value in values:
        yield( value )


def MUTATOR_STRING_OVERFLOW(raw, keep_orginal_size=False):
    """Insert big buffers to attempt triggering overflows."""
    values = [
        b'A'     * 10000,
        b'\xff'  * 10000,
        b'%x'    * 5000,
        ]

    for value in values:
        if keep_orginal_size:
            if len(value) > len(raw):
                continue

        yield( value )


def MUTATOR_CHAR(original_data, keep_orginal_size=False):
    """Return all possible bytes in [0, 256[."""
    values = range(0, 256)
    for value in values:
        yield( chr(value) )
    return


def MUTATOR_SHORT(original_data, keep_orginal_size=False):
    """Return all possible bytes in [0, 65536[."""
    values = range(0, 65536)
    for value in values:
        yield( struct.pack("<H", value) )
    return


def MUTATOR_SHORT_OVERFLOW(original_data, keep_orginal_size=False):
    """Insert incorrect short values (2 bytes) to attempt triggering overflows."""
    values = [ 0, 0x1000, 0xf000, 0xffff, 0xfffe, 0x8000, ]
    for value in values:
        yield( struct.pack("<H", value) )
    return


def MUTATOR_INTEGER_OVERFLOW(original_data, keep_orginal_size=False):
    """Insert incorrect int values (4 bytes) to attempt triggering overflows."""
    values = [
        0,
        0x100,
        0x1000,
        0x10000,
        0x100000,
        0xffffffff,
        0xfffffffe,
        0x80000000,
        0x7fffffff,
        0x7ffffffe,
        0x3fffffff,
        ]

    for value in values:
        yield( struct.pack("<I", value) )

    return

def MUTATOR_LONG_OVERFLOW(original_data, keep_orginal_size=False):
    """Insert incorrect long values (8 bytes) to attempt triggering overflows."""
    values = [ 0,
           0xf000000000000000, 0xffffffffffffffff,
           0xfffffffffffffffe, 0x8000000000000000,
           0x7fffffffffffffff, 0x7ffffffffffffffe,
           0x3fffffffffffffff, ]

    for value in values:
        yield( struct.pack("<Q", value) )

    return

def MUTATOR_SQL_INJECTION(original_data, keep_orginal_size=False):
    """Insert known SQL injection patterns."""
    values = [ b"' OR 1=1;-- ", b"') OR 1=1;--",
               b'" OR 1=1;-- ', b'") OR 1=1;--',
    ]

    for value in values:
        yield( value )

    return

def MUTATOR_HTML_TAGS(original_data, keep_orginal_size=False):
    """Iterate over all known HTML tags."""
    values = [ # from http://www.w3schools.com/tags
        "a",
        "abbr",
        "acronym",
        "address",
        "applet",
        "area",
        "article",
        "aside",
        "audio",
        "b",
        "base",
        "basefont",
        "bdi",
        "bdo",
        "big",
        "blockquote",
        "body",
        "br",
        "button",
        "canvas",
        "caption",
        "center",
        "cite",
        "code",
        "col",
        "colgroup",
        "command",
        "datalist",
        "dd",
        "del",
        "details",
        "dfn",
        "dialog",
        "dir",
        "div",
        "dl",
        "!DOCTYPE",
        "dt",
        "em",
        "embed",
        "fieldset",
        "figcaption",
        "figure",
        "font",
        "footer",
        "form",
        "frame",
        "frameset",
        "h1",
        "h6",
        "head",
        "header",
        "hgroup",
        "hr",
        "html",
        "i",
        "iframe",
        "img",
        "input",
        "ins",
        "kbd",
        "keygen",
        "label",
        "legend",
        "li",
        "link",
        "main",
        "map",
        "mark",
        "menu",
        "meta",
        "meter",
        "nav",
        "noframes",
        "noscript",
        "object",
        "ol",
        "optgroup",
        "option",
        "output",
        "p",
        "param",
        "pre",
        "progress",
        "q",
        "rp",
        "rt",
        "ruby",
        "s",
        "samp",
        "script",
        "section",
        "select",
        "small",
        "source",
        "span",
        "strike",
        "strong",
        "style",
        "sub",
        "summary",
        "sup",
        "table",
        "tbody",
        "td",
        "textarea",
        "tfoot",
        "th",
        "thead",
        "time",
        "title",
        "tr",
        "track",
        "tt",
        "u",
        "ul",
        "var",
        "video",
        "wbr",
        ]

    for value in values:
        yield( value )

    return


def MUTATOR_BITFLIP(raw, keep_orginal_size=False):
    """Performs bitflipping on input buffer."""

    def bitflip(c, i):
        """Horrible hackish implem of bitflipping: flips `i`-th bit of `c`"""
        r = ''
        for j, x in enumerate(bin(c)[2:]):
            if j==i:
                if x == '0':
                    r+= '1'
                else:
                    r+='0'
            else:
                r+=x

        return int(r, 2)


    original = bytearray(raw[:])

    for i, v in enumerate(original):

        for j in range(7, -1, -1):
            mutated = bytearray(raw[:])
            v2 = bitflip(v, j)
            mutated[i] = v2
            yield( str(mutated) )

    return
