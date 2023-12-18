import pyshark
import pandas as pd
from matplotlib import pyplot as plt

def analyze_pcapng(file_path, packet_limit=2000):
    try:
        capture = pyshark.FileCapture(file_path, display_filter="rtps")
        data = []

        for packet in capture:
            if 'UDP' in packet:
                src_port = packet[packet.transport_layer].srcport
                dst_port = packet[packet.transport_layer].dstport
                src_ip = packet.ip.src  # Extract source IP
                dst_ip = packet.ip.dst  # Extract destination IP
                timestamp_ns = int(float(packet.sniff_timestamp) * 1e9)  # Convert to nanoseconds

                data.append((src_port, dst_port, timestamp_ns, src_ip, dst_ip))

            if len(data) >= packet_limit:
                break

        throughput_df = analyze_port_pair_traffic(data)
        print("Throughput Percentage:")
        print(throughput_df)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        capture.close()


def analyze_port_pair_traffic(data):

    throughput_data = []

    grouped_data = {}
    for src_port, dst_port, _, _,  dst_ip in data:
        if dst_ip not in grouped_data:
            grouped_data[dst_ip] = {}
        if (src_port, dst_port) not in grouped_data[dst_ip]:
            grouped_data[dst_ip][(src_port, dst_port)] = 0
        grouped_data[dst_ip][(src_port, dst_port)] += 1

    for dst_ip in grouped_data:
        total_data = sum(grouped_data[dst_ip].values())
        for (src_port, dst_port), count in grouped_data[dst_ip].items():
            throughput_percentage = (count / total_data) * 100 if total_data > 0 else 0
            throughput_data.append({
                'src_port': src_port,
                'dst_port': dst_port,
                'dst_ip': dst_ip,
                'data_size': count,
                'throughput_percentage': throughput_percentage
            })

    throughput_df = pd.DataFrame(throughput_data)

    plot_throughput_by_dst_ip(throughput_df)
    return throughput_df
def plot_throughput_by_dst_ip(df):

    data_sum_by_dst_ip = df.groupby('dst_ip')['data_size'].sum()

    labels = [f'{ip} ({size} packets)' for ip, size in data_sum_by_dst_ip.items()]

    plt.figure(figsize=(10, 6))
    plt.pie(data_sum_by_dst_ip, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Throughput Distribution by Destination IP')
    plt.show()
    unique_dst_ips = df['dst_ip'].unique()
    for dst_ip in unique_dst_ips:
        plot_throughput_by_dst_port(df, dst_ip)

def plot_throughput_by_dst_port(df, dst_ip):

    data_sum_by_dst_port = df[df['dst_ip'] == dst_ip].groupby('dst_port')['data_size'].sum()
    labels = [f'Port {port} ({size} packets)' for port, size in data_sum_by_dst_port.items()]
    plt.figure(figsize=(10, 6))
    plt.pie(data_sum_by_dst_port, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title(f'Throughput Distribution by Destination Port within {dst_ip}')
    data_sum_by_dst_port = df[df['dst_ip'] == dst_ip].groupby('dst_port')['data_size'].sum()
    labels = [f'Port {port} ({size} packets)' for port, size in data_sum_by_dst_port.items()]
    plt.figure(figsize=(10, 6))
    plt.pie(data_sum_by_dst_port, labels=labels, autopct='%1.1f%%', startangle=140)
    title = f'Throughput Distribution by Destination Port within {dst_ip}'
    plt.title(title)

    # make it easier to read the labels by save them.
    filename = title.replace(' ', '_') + '.png'
    plt.savefig(filename)
    plt.show()
    print(f"Plot saved as {filename}")

file_path = 'sample_rtps_5000.pcap'
analyze_pcapng(file_path)
