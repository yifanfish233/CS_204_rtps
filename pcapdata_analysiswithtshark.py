import subprocess
import re
import pandas as pd
from matplotlib import pyplot as plt


def extract_data(rtps_data, record_number):
    domain_id_match = re.search(r'domainId=(\d+)', rtps_data)
    participant_idx_match = re.search(r'participantIdx=(-?\d+)', rtps_data)
    nature_match = re.search(r'nature=([\w_]+)', rtps_data)
    submessage_ids = re.findall(r'submessageId: (\w+)', rtps_data)
    packet_type = 'OTHER'
    if 'DATA' in submessage_ids:
        packet_type = 'DATA'
    elif 'HEARTBEAT' in submessage_ids:
        packet_type = 'HEARTBEAT'
    elif 'ACKNACK' in submessage_ids:
        packet_type = 'ACKNACK'

    return {
        'Record Number': record_number,
        'DomainId': int(domain_id_match.group(1)) if domain_id_match else None,
        'ParticipantIdx': int(participant_idx_match.group(1)) if participant_idx_match else None,
        'Nature': nature_match.group(1) if nature_match else None,
        'SubmessageIds': ', '.join(submessage_ids),  # 将列表转换为字符串
        'PacketType': packet_type
    }


def visualize_packet_events(df):
    color_map = {'DATA': 'blue', 'HEARTBEAT': 'red', 'ACKNACK': 'green', 'OTHER': 'grey'}
    plt.figure(figsize=(12, 8))


    for packet_type, color in color_map.items():
        record_numbers = df[df['PacketType'] == packet_type]['Record Number']
        plt.vlines(record_numbers, 0, 1, colors=color, label=packet_type, linewidth=2)

    plt.xlabel('Record Number')
    plt.yticks([])
    plt.title('Packet Type Events Over Records')
    plt.legend()
    filename = 'Packet_Type_Events_Over_Records.png'
    plt.savefig(filename)
    print(f"Plot saved as {filename}")
    # plt.show()

def visualize_packet_types_over_records(df):
    # 确保 'Record Number' 是有序的
    df.sort_values('Record Number', inplace=True)

    # 初始化每种类型的累积计数
    cumulative_counts = {
        'DATA': [],
        'HEARTBEAT': [],
        'ACKNACK': []
    }
    current_counts = {'DATA': 0, 'HEARTBEAT': 0, 'ACKNACK': 0}

    # 遍历每条记录，更新累积计数
    for _, row in df.iterrows():
        packet_type = row['PacketType']
        if packet_type in current_counts:
            current_counts[packet_type] += 1

        for type_key in cumulative_counts:
            cumulative_counts[type_key].append(current_counts[type_key])

    # 绘制折线图
    plt.figure(figsize=(12, 8))
    for type_key, counts in cumulative_counts.items():
        plt.plot(df['Record Number'], counts, label=type_key)

    plt.xlabel('Record Number')
    plt.ylabel('Cumulative Count')
    plt.title('Cumulative Packet Types Over Records')
    plt.legend()
    filename = 'Cumulative_Packet_Types_Over_Records.png'
    plt.savefig(filename)
    print(f"Plot saved as {filename}")
    plt.show()
def process_rtps_records(file_path, record_total):
    extracted_data_list = []
    try:
        capture_flag = f"-c {record_total}" if record_total != -1 else ""
        command = f'tshark -r {file_path} -Y "udp" {capture_flag} -V'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            output = result.stdout
            rtps_pattern = re.compile(
                r'Frame (\d+):.*?Real-Time Publish-Subscribe Wire Protocol.*?(?=Frame \d+:|\Z)',
                re.DOTALL
            )

            for match in rtps_pattern.finditer(output):
                frame_number = int(match.group(1))  # 提取帧号
                rtps_data = match.group(0)
                extracted_data = extract_data(rtps_data, frame_number)
                extracted_data_list.append(extracted_data)
    except Exception as e:
        print(f"An error occurred: {e}")
    df = pd.DataFrame(extracted_data_list)
    print(df)
    visualize_packet_events(df)
    visualize_packet_types_over_records(df)

file_path = 'sample_rtps_5000.pcap'
record_total = 5000
process_rtps_records(file_path, record_total)
