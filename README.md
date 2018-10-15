# CodingChallenge2018
### Description
- This is a coding challenge for Illumio summer 2019 software internship.

- The code implements a simple firewall check. It imports "allow" rules from a csv file and the code does packet checking in Firewall.java file.

### How I tested my solution
- I didn't have much time left to write unit tests or integration tests so I added a simple main() method in Firewall.java to test my code. First, I created a csv file with example rules (test.csv). Then, I tested each rule with specific inputs. For each rule, the first few test cases have inputs that follows the rule (including the cases that checks the boundaries for ranges since boundaries are inclusive) and the last couple of test cases would fail to pass the rule. I also tested a few test cases with bad inputs like empty parameters, invalid port and ip to make sure the code handles invalid cases.

### Any interesting coding, design, or algorithmic choices you’d like to point out
- Since there can be 4 distinct combinations of directions and protocols (inbound&tcp, inbound&udp, outbound&tcp, outbound&udp), I used 4 hashmaps to store the corresponding ports and ip addresses for each combination. During the checking process in accept_packet(), I used simple conditional statements to check which combination of direction and protocol that input packet has and then try to check if the packet follows any rules in that particular hashmap.


- The check for ip ranges took me a while to came up with. In my first try, I replaced the "." in ip addresses and directly converted ip addresses without the dot to int and the two integers would be my boundary for the range. However, ip addresses are from 0.0.0.0-255.255.255.255 and the max value for integer is 2,147,483,647, which does not work. Then, I created a separate funtion to convert the IP addresses to 32-bit integers for comparision. I think this makes more sense because ipv4 address is initially composed by four 8 binary digits connected by dots.

### Any refinements or optimizations that I would’ve implemented if you had more time
- I used hash map to store port-ip pair based on rules. However, if port input is a range, I saved all ports individually with its targeted ip/ip ranges. If the port range is very large, it will take a lot of memory. If I have more time to do research and have more information, I would change the storage data structure to be something like a TreeMap. In treeMap, the key are natually ordered. Therefore, we can perform a binary search to find the closes port range then check if the input port is in the rule (Here is the tradeoff between space and time complexity). If port is a range, we can store the higher bound in the first element in the value list. Ports are stored as an integer and ip addresses are strings. A simple type check can determine if the closest port has a range instead of storing every port as a key in the map. I will explain my point with an example.

TreeMap Example: TreeMap A for inbound & tcp

| Key  | Value  |
|---|---|
| Port  | IP/IP Range  |
| 1   | ["192.168.1.1"]  |
| 20  | ["192.168.2.1", "192.168.2.56"]  |
| 50  | [70, "190.1.2.1"]   |
| 80  | [85, "190.1.0.1", "190.5.0.0"] |


accept_packet("inbound", "tcp", 60, "190.1.2.1")
1. Do a binary search on A.keySet() to get the closest value to 60 and is smaller than 60 (in this case 50)
2. Check if there is an upper bound in value list (in this case, yes 70)
3. Since 70 > 60, port is acceptable, then go on to check ip ranges





### My team choice
1. Platform
2. Data
3. Policy

