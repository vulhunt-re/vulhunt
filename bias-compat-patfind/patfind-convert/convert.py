import click
import yaml

from lxml import etree

HTABLE = "0123456789abcdef"

def format_pattern(bytes, mask):
    pat = ""
    for i, (v, m) in enumerate(zip(bytes, mask)):
        if i != 0:
            pat += " "
        if m == 0x00:
            pat += ".."
        elif m == 0x0f:
            pat += "."
            pat += HTABLE[v >> 4]
        elif m == 0xf0:
            pat += HTABLE[v & 0xf]
            pat += "."
        elif m == 0xff:
            pat += HTABLE[v >> 4]
            pat += HTABLE[v & 0xf]
        else:
            for i in reversed(range(8)):
                if m >> i & 1 == 0:
                    pat += "."
                else:
                    pat += HTABLE[v >> i & 1]
    return pat


# NOTE:
# _parse_ghidra_pattern_item and _convert_ghidra_pattern_to_image_and_mask
# have been taken/adapted from https://github.com/david-lazar/IDAPatternSearch
#

def _parse_ghidra_pattern_item(pattern_item, element_length):
    '''
    This function parses a given Ghidra pattern item (pattern_item) which is one item from a Ghidra pattern.
    The function also uses (element_length) to determine if it is:
        * Hex item (starting with 0x which was already omitted before calling this function)
          which in this case (element_length) == 4
        * Bitfield item
          which in this case (element_length) == 1
    The '.' characther in both item types represents a wildcard Bit/Byte depends on the item type (Hex/Bitfield).
    This function returns two values: (image, mask)
        * image - represents the item image to search by the pattern.
        * mask -  represents the item mask that can be used to mask out the matched bytes and check against the image
    '''
    cur_image = 0
    cur_mask = 0
    for element in pattern_item:
        if element == '.':
            # Wildcard element
            # mask should be zeros (in bits), image should be zero (lets say 0)
            cur_mask = cur_mask << element_length
            cur_image = cur_image << element_length
        else:
            # mask should be 1's (in bits), image is same as half_byte
            cur_mask = cur_mask << element_length
            if element_length == 1:
                # bit element
                cur_mask += 1
            else:
                # half byte element
                cur_mask += 0xf

            cur_image = cur_image << element_length
            if element_length == 1:
                # bit element
                cur_image += int(element, 2)
            else:
                # half byte element
                cur_image += int(element, 16)
    return cur_image, cur_mask


def _convert_ghidra_pattern_to_image_and_mask(ghidra_pattern):
    '''
    This function parses a given Ghidra pattern (ghidra_pattern) after extracted from the XML file already.
    Every item is parsed and at the end, all the items are joined into 2 returned byte strings: image and mask.
    The function returns a dictionary with the keys:
        * image - represents the image to search by the pattern.
        * mask - represents the mask that can be used to mask out the matched bytes and check against the image
    The values in the dictionary are byte-strings.
    '''
    ghidra_pattern = ghidra_pattern.split()
    image = [b'']*len(ghidra_pattern)
    mask = [b'']*len(ghidra_pattern)
    for i in range(len(ghidra_pattern)):
        pattern_item = ghidra_pattern[i]
        pattern_byte_len = 0  # Number of bytes presetend by pattern
        cur_image = 0  # Image of current pattern item
        cur_mask = 0  # Mask of current pattern item

        if '0x' in pattern_item[0:2]:
            # Hex parsing
            pattern_item = pattern_item[2:]  # Remove '0x' at start
            if len(pattern_item) == 2 or len(pattern_item) == 4 or len(pattern_item) == 8:
                cur_image, cur_mask = _parse_ghidra_pattern_item(
                    pattern_item, 4)

                # 1 or 2 or 4 byte format
                pattern_byte_len = len(pattern_item)//2
            else:
                return None
        else:
            # Bit parsing
            if len(pattern_item) == 8:
                cur_image, cur_mask = _parse_ghidra_pattern_item(
                    pattern_item, 1)
                # 1 byte format is the only case for bit parsing
                pattern_byte_len = 1
            else:
                return None

        # Convert from int to bytes
        image[i] = cur_image.to_bytes(pattern_byte_len, byteorder='big')
        mask[i] = cur_mask.to_bytes(pattern_byte_len, byteorder='big')

    bytes = b''.join(image)
    mask = b''.join(mask)

    return format_pattern(bytes, mask)


def parse_pattern_text(pat: str):
    if pat is None or len(pat) == 0:
        return None

    return _convert_ghidra_pattern_to_image_and_mask(pat)


def parse_pattern(elt: etree.Element):
    data = []
    context = []

    for elt in elt.iterchildren():
        if elt.tag == "data" and (pat := parse_pattern_text(elt.text)):
            data.append(pat)
        elif elt.tag == "setcontext" and (name := elt.attrib.get("name")) and (value := elt.attrib.get("value")):
            context.append({"name": name, "value": int(value)})

    return {
        "pattern": {
            "patterns": data,
            "context": context,
        }
    }


def parse_patternpairs(elt: etree.Element):
    pre = None
    post = None

    total_bits = int(elt.attrib.get("totalbits", 0))
    post_bits = int(elt.attrib.get("postbits", 0))

    for elt in elt.iterchildren():
        if elt.tag == "postpatterns":
            post = elt
        elif elt.tag == "prepatterns":
            pre = elt

    if post is None:
        return None

    post_data = []
    post_context = []
    pre_data = []

    if pre is not None:
        for elt in pre.iterchildren():
            if elt.tag == "data" and (pat := parse_pattern_text(elt.text)):
                pre_data.append(pat)

    for elt in post.iterchildren():
        if elt.tag == "data" and (pat := parse_pattern_text(elt.text)):
            post_data.append(pat)
        elif elt.tag == "setcontext" and (name := elt.attrib.get("name")) and (value := elt.attrib.get("value")):
            post_context.append({"name": name, "value": int(value)})

    return {
        "pattern-group": {
            "total-bits": total_bits, # total-bits = total # of bits pre/post that must be a 0/1 not '.'
            "post-bits": post_bits,   # post-bits = number of bits that are 0/1 not '.' that must come from post pattern bits
            "post": {
                "patterns": post_data,
                "context": post_context,
            },
            "pre": pre_data,
        },
    }


def parse(path, arch):
    with open(path, "r") as f:
        t = etree.XML(f.read())

        if t.tag != "patternlist":
            raise ValueError("invalid file format")

        pats = []

        for elt in t.iterchildren():
            if elt.tag == "patternpairs" and (pat := parse_patternpairs(elt)):
                pats.append(pat)
            elif elt.tag == "pattern" and (pat := parse_pattern(elt)):
                pats.append(pat)

        return {
            "author": "Binarly",
            "version": "0.1.0",
            "architecture": arch,
            "patterns": pats,
        }


@click.command()
@click.argument('input', type=click.Path(exists=True))
@click.argument('output', type=click.Path())
@click.option('-a', '--architecture', 'arch', default='*:*:*:*:*')
def main(input, output, arch):
    v = parse(input, arch)
    with open(output, "w") as f:
        yaml.dump(v, f)


if __name__ == '__main__':
    main()
