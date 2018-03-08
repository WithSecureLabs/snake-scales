import bz2
import hashlib
import subprocess

import bitstring
# import pefile

from snake import error


def code_language(pe, file_path):  # pylint: disable=invalid-name, too-many-branches
    iat, language = [], []
    strings = str(subprocess.check_output(["strings", file_path]), encoding="utf-8").split('\n')

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for peimport in pe.DIRECTORY_ENTRY_IMPORT:
            iat.append(peimport.dll.decode("utf-8"))

    # VB Check
    if not language.__contains__('VB'):
        for mod in iat:
            if 'VB' in mod:
                language.append('VB')

    # .NET Check
    if not language.__contains__('.NET'):
        for mod in iat:
            if 'mscoree.dll' in mod:
                language.append('.NET')

    # C Check
    if not language.__contains__('C/C++'):
        for mod in iat:
            if 'MSVCR' in mod.upper() or 'c++' in mod:
                language.append('C/C++')

    # Super advanced strings checking
    for string in strings:
        # AutoIT Check
        if not language.__contains__('AutoIt'):
            if 'AU3!' in string or 'AutoIt script' in string:
                language.append('AutoIt')

        # Borland Delphi Check
        if not language.__contains__('Delphi'):
            if 'Borland' in string:
                if 'Delphi' in string.split('\\'):
                    language.append('Delphi')

        # VB .NET
        if not language.__contains__('VB .NET'):
            if 'Compiler' in string:
                if 'VisualBasic' in string.split('.'):
                    language.append('VB .NET')

    if len(language) == 1:
        return str(language[0])

    output = ''
    for lang in list(set(language)):
        output += lang + ', '
    return str(output)


def get_certificate(pe):  # pylint: disable=invalid-name
    # TODO: Finish this!
    # pe_security_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    # address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pe_security_dir].VirtualAddress

    # addr = pe.write()[address +8]

    return 'TBC'


# FIXME: Problems with pehash implementations: https://gist.github.com/wxsBSD/07a5709fdcb59d346e9e
# TODO: Double check for accuracy and cite correctly
# Taken from Viper: https://github.com/viper-framework/viper/blob/master/viper/modules/pehash/pehasher.py
def calculate_pehash(exe):  # pylint: disable=too-many-locals, too-many-statements
    try:
        # image characteristics
        img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
        # pad to 16 bits
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:8] ^ img_chars[8:16]

        # start to build pehash
        pehash_bin = bitstring.BitArray(img_chars_xor)

        # subsystem -
        sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
        # pad to 16 bits
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
        pehash_bin.append(sub_chars_xor)

        # Stack Commit Size
        stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = stk_size.bin.zfill(32)
        # now xor the bits
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
        # pad to 8 bits
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        # Heap Commit Size
        hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = hp_size.bin.zfill(32)
        # now xor the bits
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
        # pad to 8 bits
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        # Section chars
        for section in exe.sections:
            # virtual address
            sect_va = bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            sect_va_bits = sect_va[8:32]
            pehash_bin.append(sect_va_bits)

            # rawsize
            sect_rs = bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs.bin.zfill(32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:32]
            pehash_bin.append(sect_rs_bits)

            # section chars
            sect_chars = bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
            pehash_bin.append(sect_chars_xor)

            # entropy calulation
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.write()[address + size:]
            if size == 0:
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:8])
                continue
            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            # k = round(bz2_size / size, 5)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:8])

        sha1 = hashlib.sha1()
        sha1.update(pehash_bin.tobytes())
        return str(sha1.hexdigest())

    except Exception as err:
        raise error.CommandError('An error occurred with calculate_pehash: %s' % err)
