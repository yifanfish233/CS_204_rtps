# CS_204_rtps
Course project collection repo. for CS 204 by Yifan Yu

## ROS2 DDS Communication Analysis Study
This project is to analyze the DDS communication between Autoware and AWSIM. The analysis is based on the captured DDS communication packets by Wireshark. The analysis is based on the following aspects:
- DDS communication throughput(pyshark)
- DDS communication events(tshark)


## Requriement
- ROS2 Galactic (Ubuntu 20.04)
- Autoware.Universe
- AWSIM
- Python3
- Pyshark
- Tshark
- pandas
- numpy
- matplotlib

Autoware.Universe and AWSIM are both follow the installation guide by the GitHub: https://github.com/tier4/AWSIM 

Run independently of these two python scripts, will generate the plots for evaluation.
