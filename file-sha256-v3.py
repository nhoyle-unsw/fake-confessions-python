# Python program to find SHA256 hash string of a file
import hashlib
import re
from collections import Counter
import sys
# https://www.tutorialkart.com/python/python-read-file-as-string/


def printd(*args):
    # print(args)
    pass


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


# https://www.geeksforgeeks.org/python-count-occurrences-of-a-character-in-string/

REAL_FILENAME_DEFAULT = "confession_real.txt"
REAL_FILE_SHA256 = "ee2b34b775d70cd1e23ff42a7ed39731419a443c4f08b062e96015e6e951588d"
real_file_contents = read_file(REAL_FILENAME_DEFAULT)
# real_file_lines = open(real_file_name).readlines()
real_file_line_count = real_file_contents.count('\n')

FAKE_FILENAME_DEFAULT = "confession_fake.txt"
FAKE_FILE_SHA256 = "44026d38d615a11633ed19548eeaea15b38e99fcc670277a42c80a5edc26df11"
fake_file_contents = read_file(FAKE_FILENAME_DEFAULT)
# fake_file_lines = open(fake_file_name).readlines()
fake_file_line_count = fake_file_contents.count('\n')


# https://www.tutorialspoint.com/python3/python_command_line_arguments.htm


def main():
    printd('Number of arguments:', len(sys.argv), 'arguments.')
    printd('Argument List:', str(sys.argv))
    args = sys.argv[1:]
    if len(args) == 2:
        real_file_contents = read_file(args[0])
        fake_file_contents = read_file(args[1])
    else:
        print("command format: python -u file-sha256-v3.py filename")
        print("You supllied args:", args)
        exit(1)
    check_original_files(real_file_contents, fake_file_contents)

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
    print("\n\n\n\n\n")
    for file_version in range(2 ** real_file_line_count):
        binary_pattern = bin(file_version).replace("0b", "")
        printd("-- New File ------------------------------------")
        printd("outer file_version:", file_version,
               "binary_pattern:", binary_pattern)
        last_line_index = real_file_line_count - 1
        updated_file_content = ""
        # https://www.javainterviewpoint.com/iteration-index-in-for-loop-in-python/
        split_lines = real_file_contents.split("\n")
        printd("split_lines:", len(split_lines), split_lines)
        index = 0
        for bit in reversed(binary_pattern):
            line = split_lines[last_line_index-index]
            printd("inner index: ", index)
            printd("inner line_index: ", last_line_index)
            printd("inner line: ", line)
            printd("inner bit:", bit)
            updated_file_line = ("orig: " + line +
                                 ("\n" if bit == "0" else " \n"))
            split_lines[last_line_index-index] = updated_file_line
            # input("waiting inner...\n")
            index += 1
            if index >= len(binary_pattern):
                break
        updated_file_content = "\n".join(split_lines)
        printd("updated file verison#:", file_version,
               "binary_pattern:", binary_pattern, "\n")
        printd("File content: start[" + updated_file_content + "]end")
        print(sha256_string(updated_file_content))

        # input("waiting outer...\n\n")

    # places a token at the end of the line


def check_original_files(real_file_contents, fake_file_contents):
    # check originals
    print("Check original files: ")
    #input("waiting ...\n")
    print("Real file:\n\nstart[" + real_file_contents + "]end")
    print("Real file lines: ", real_file_line_count)
    print("Fake file:\n\nstart[" + fake_file_contents + "]end")
    print("Fake file lines: ", fake_file_line_count)
    print("SHA256 real: " + sha256_string(real_file_contents))
    print("SHA256 fake: " + sha256_string(fake_file_contents))
    if sha256_string(real_file_contents) == REAL_FILE_SHA256 and sha256_string(fake_file_contents) == FAKE_FILE_SHA256:
        print("Original files SHA256 match.")
    else:
        print("Original files do not match thier original SHA256. Won't run any further.")
        exit(1)


if __name__ == "__main__":
    main()
