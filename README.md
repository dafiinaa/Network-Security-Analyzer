# Network-Security-Analyzer
This tool analyzes network traffic, detects suspicious packets, and displays volume traffic statistics.

## General 
This project serves as a basic network security analyzer that analyzes incoming and outgoing network traffic. It identifies suspicious packet based on criteria such as very high volume sender or receiver IP address and their accessibility to some protocols. The user can choose to allow or deny suspicious packets. The tool also visualizes the traffic volume per IP address using a graph for easy analysis. 

## Requirements
 Python Interpreter. Ensure that you have a Python interpreter installed on your system.

## Installation 
**1. Clone the repository:**

git clone https://github.com/dafiinaa/Network-Security-Analyzer.git


**2. Install required packages:**
  * pip install scapy pandas 
  * pip install matplotlib

## Usage 
1. Navigate to the project directory Network-Security-Analyzer.py
2. Run the Network-Security-Analyzer.py file 
3. Click the Start Sniffing Button in the application's interface
4. Respond to notifications choosing Deny or Allow buttons for suspicious packets.
5. View traffic volume graph that updates based on IP address traffic. 


## Libraries
* tkinter
* scapy
* threading
* queue
* matplotlib



## Contributors
- [Blinera Mehmeti](https://github.com/blineramehmeti1) 
- [Clirim Matoshi](https://github.com/Clirim99)
- [Dafina Sadiku](https://github.com/dafiinaa) 
