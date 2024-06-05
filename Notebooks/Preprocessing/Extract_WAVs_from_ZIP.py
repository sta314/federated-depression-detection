import os
import tarfile
import shutil
from tqdm import tqdm

tar_files_directory = '.'

output_directory_wav = 'extracted/wav'
output_directory_transcript = 'extracted/transcript'

os.makedirs(output_directory_wav, exist_ok=True)

for tar_filename in tqdm(os.listdir(tar_files_directory)):
    if tar_filename.endswith('.tar'):
        tar_file_path = os.path.join(tar_files_directory, tar_filename)
        file_num = tar_filename.split("_")[0]
        with tarfile.open(tar_file_path, 'r') as tar:
            folder_name = os.path.splitext(tar_filename)[0]
            wav_filename = file_num + "_AUDIO.wav"
            wav_file_path = folder_name + "/" + wav_filename
            try:
                member = tar.getmember(wav_file_path)
                member.name = os.path.basename(member.name)
                tar.extract(member, output_directory_wav)
            except KeyError:
                print(f"Wav file {wav_filename} not found in {tar_filename}")

            transcript_filename = file_num + "_Transcript.csv"
            transcript_file_path = folder_name + "/" + transcript_filename
            try:
                member = tar.getmember(transcript_file_path)
                member.name = os.path.basename(member.name)
                tar.extract(member, output_directory_transcript)
            except KeyError:
                print(f"Transcript file {wav_filename} not found in {transcript_filename}")

print("All files collected successfully.")