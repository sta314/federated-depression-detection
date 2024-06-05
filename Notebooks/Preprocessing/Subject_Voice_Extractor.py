import pandas as pd
from pydub import AudioSegment
from pathlib import Path
from pydub.playback import play
import os
from tqdm import tqdm

def crop_audio(audio_segment, start_time, end_time, output_path):
    cropped_audio = audio_segment[start_time * 1000 : end_time * 1000]  # times are in seconds
    cropped_audio.export(output_path, format="wav")

def concat_audio(crop_folder, output_file):
    audio = AudioSegment.silent(duration=0)

    for file in Path(crop_folder).glob("*.wav"):
        segment = AudioSegment.from_wav(file)
        audio += segment

    audio.export(output_file, format="wav")

def process_csv(csv_path, wav_folder, crop_folder, merge_folder):
    file_num = Path(csv_path).stem.split("_")[0]
    wav_file_path = f"{wav_folder}/{file_num}_AUDIO.wav"
    audio_segment = AudioSegment.from_wav(wav_file_path)

    df = pd.read_csv(csv_path)
    left_boundary = 0 # this is used since there is corrupted data in transcripts, this provides consistency

    for index, row in df.iterrows():

        if index < 10 or index > df.shape[0] - 6: # discard first 10 and last 5 intervals
            continue

        start_time = float(row['Start_Time'])
        end_time = float(row['End_Time'])
        end_time += 0.75 # add some offset to end time

        crop_output_folder = f"{crop_folder}/{file_num}"
        merge_output_folder = f"{merge_folder}/{file_num}"
        
        if left_boundary <= start_time:

            # crop & save

            crop_output_file_path = f"{crop_output_folder}/{file_num}_AUDIO_{index}.wav"
            os.makedirs(crop_output_folder, exist_ok=True)
            crop_audio(audio_segment, start_time, end_time, crop_output_file_path)

            # print(f"Cropped {wav_file_path} from {start_time} to {end_time}, idx: {index}. Saved to {crop_output_file_path}")

            left_boundary = start_time

    # merge & save
    merge_output_file_path = f"{merge_output_folder}/{file_num}_AUDIO_M.wav"
    os.makedirs(merge_output_folder, exist_ok=True)
    concat_audio(crop_output_folder, merge_output_file_path)
    # print(f"Merged audio segments into {merge_output_file_path}")

transcript_folder = Path("transcript")
wav_folder = Path("wav")
crop_folder = Path("crop")
merge_folder = Path("merge")

# Iterate through each CSV file in the transcript folder
for transcript_file in tqdm(transcript_folder.glob("*.csv")):
    process_csv(transcript_file, wav_folder, crop_folder, merge_folder)