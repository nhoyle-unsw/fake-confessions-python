# Python program to find SHA256 hash string of a file
from __future__ import print_function
import hashlib
import sys
import argparse

REAL_FILENAME = "confession_real.txt"
REAL_FILE_SHA256 = "ee2b34b775d70cd1e23ff42a7ed39731419a443c4f08b062e96015e6e951588d"

FAKE_FILENAME = "confession_fake.txt"
FAKE_FILE_SHA256 = "44026d38d615a11633ed19548eeaea15b38e99fcc670277a42c80a5edc26df11"

parser = argparse.ArgumentParser()
parser.add_argument("filename", help="The name of the file to hash attack")
parser.add_argument("-d", "--debug", action="store_true",
                    help="Output debug statements (you need to press Enter to see each line of the output)")
parser.add_argument("-b", "--binary-pattern", action="store_true",
                    help="Include the binary pattern in the output. The binary pattern is used to insert spaces in the file lines (note the binary pattern starts at the bottom of the file, a 1 is a space 0 is do nothing)")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
args = parser.parse_args()
is_debug = args.debug


def printd(*args, **kwargs):
    if is_debug:
        input()
        print(*args, file=sys.stdout, **kwargs)
    else:
        pass

# https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# https://www.tutorialkart.com/python/python-read-file-as-string/


def read_file(file_name):
    text_file = open(file_name)
    data = text_file.read()
    text_file.close()
    return data

# https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html


def file_sha256():
    filename = input("Enter the input file name: ")
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())

# https://medium.com/@dwernychukjosh/sha256-encryption-with-python-bf216db497f9


def sha256_string(string):
    sha_signature = hashlib.sha256(string.encode()).hexdigest()
    return sha_signature

# https://www.tutorialspoint.com/python3/python_command_line_arguments.htm
# https://www.onlinetutorialspoint.com/python/how-to-pass-command-line-arguments-in-python.html
# https://docs.python.org/3/howto/argparse.html#id1


def main():
    printd('Number of arguments:', len(sys.argv), 'arguments.')
    printd('Argument List:', str(sys.argv))
    file_contents = read_file(args.filename)

    '''
    https://www.w3schools.com/python/python_for_loops.asp
    https://www.pythonpool.com/python-int-to-binary/
    '''
    '''
    There are 2 ^ 30 different possibilites for the file with spaces at the end of the lines in the file.
    pPthon uses ** to raise a nuber to a power so 2 ^ 30  is: 2 ** 30 = about a billion possibilities
    We only need 30 bits to do this and 2^30 has 31 bits, so I subtract 1 to get 30 1's: 111111111111111111111111111111
    I am going to use that pattern to decide which line to put a space and which line to leave as is
    e.g. for the pattern 111000000000000000000000000000 I will insert a space in the last three lines only
    for 111111111111111111111111111111 I will put a space at the end of all lines. I am doing it backwards so
    that small number like 111000 do not just duplicate the pattern for largetr numbers like 11100000
    '''
    file_supplied_hash = sha256_string("\n".join(file_contents.split("\n")))
    printd("Original file hash:", file_supplied_hash)
    if not is_matching_an_original_file_hash(file_supplied_hash):
        eprint("ERROR: the input file does not match an original file hash")
        eprint("Your file hash:", file_supplied_hash)
        eprint("Valid orignals:")
        eprint(REAL_FILENAME, REAL_FILE_SHA256)
        eprint(FAKE_FILENAME, FAKE_FILE_SHA256)
        exit(1)
    real_file_line_count = file_contents.count('\n')
    for file_version in range(2 ** real_file_line_count):
        binary_pattern = bin(file_version).replace("0b", "")
        printd("-- New File ------------------------------------")
        printd("outer file_version:", file_version,
               "binary_pattern:", binary_pattern)
        last_line_index = real_file_line_count - 1
        updated_file_content = ""
        # https://www.javainterviewpoint.com/iteration-index-in-for-loop-in-python/
        split_lines = file_contents.split("\n")
        printd("split_lines:", len(split_lines), split_lines)
        index = 0
        for bit in reversed(binary_pattern):
            line = split_lines[last_line_index-index]
            printd("inner index: ", index)
            printd("inner line_index: ", last_line_index)
            printd("inner line: ", line)
            printd("inner bit:", bit)
            updated_file_line = line + (" " if bit == "1" else "")
            split_lines[last_line_index-index] = updated_file_line
            # input("waiting inner...\n")
            index += 1
            if index >= len(binary_pattern):
                break
        updated_file_content = "\n".join(split_lines)
        printd("updated file verison#:", file_version,
               "binary_pattern:", binary_pattern, "\n")
        printd("File content: start[" + updated_file_content + "]end")
        new_file_hash = sha256_string(updated_file_content)
        if args.binary_pattern:
            print(binary_pattern, new_file_hash)
        else:
            print(new_file_hash)
        if file_version == 0 and not is_matching_an_original_file_hash(new_file_hash):
            eprint("ERROR: file does not match and original file hash. originals:", )
            exit(1)
        # input("waiting outer...\n\n")

    # places a token at the end of the line


def is_matching_an_original_file_hash(hash_to_check):
    return True if hash_to_check == REAL_FILE_SHA256 or hash_to_check == FAKE_FILE_SHA256 else False


if __name__ == "__main__":
    main()
