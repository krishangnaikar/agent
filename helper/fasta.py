import re


def is_fasta_file(file_path):
    # Check the file extension
    if file_path.endswith((".fasta", ".fa", ".txt")):
        try:
            with open(file_path, "r") as file:
                # Read the first line
                first_line = file.readline().strip()
                # Check if it starts with '>'
                if re.match(r'^>', first_line):
                    return True
        except FileNotFoundError:
            pass
    return False


def is_fastq_file(file_path):
    # Check the file extension
    if file_path.endswith((".fastq", ".fq")):
        try:
            with open(file_path, "r") as file:
                # Read the first four lines
                first_line = file.readline().strip()
                second_line = file.readline().strip()
                third_line = file.readline().strip()
                fourth_line = file.readline().strip()

                # Check if the lines match the FASTQ format
                if (first_line.startswith('@') and third_line.startswith('+') and len(second_line) > 0 and len(
                        fourth_line) > 0):
                    return True
        except FileNotFoundError:
            pass
    return False


# Example usage:
file_path = "sample.fastq"
if is_fastq_file(file_path):
    print(f"{file_path} is a valid FASTQ file.")
else:
    print(f"{file_path} is not a valid FASTQ file.")

# Example usage:
file_path = "sample.fasta"
if is_fasta_file(file_path):
    print(f"{file_path} is a valid FASTA file.")
else:
    print(f"{file_path} is not a valid FASTA file.")