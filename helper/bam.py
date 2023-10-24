import pysam

def is_bam_file_advanced(file_path):
    try:
        with pysam.AlignmentFile(file_path, "rb") as bam_file:
            return bam_file.check_header()
    except pysam.utils.SamtoolsError:
        return False

# Example usage:
file_path = "sample.bam"
if is_bam_file_advanced(file_path):
    print(f"{file_path} is a valid BAM file.")
else:
    print(f"{file_path} is not a valid BAM file.")