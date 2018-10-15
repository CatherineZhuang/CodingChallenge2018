import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

public class Firewall {
    // inbound tcp
    static Map<Integer, List<String>> typeOne = new HashMap<>();
    // outbound tcp
    Map<Integer, List<String>> typeTwo = new HashMap<>();
    // inbound udp
    Map<Integer, List<String>> typeThree = new HashMap<>();
    // outbound udp
    Map<Integer, List<String>> typeFour = new HashMap<>();

    public Firewall(String csvPath) {
        // read rules in csv file and store it
        BufferedReader br = null;
        String line = "";
        String cvsSplitBy = ",";
        
        try {
            // import csv file and read line by line
            br = new BufferedReader(new FileReader(csvPath));
            while ((line = br.readLine()) != null) {
                String[] data = line.split(cvsSplitBy);
                List<String> ipRangeMap = new ArrayList<>();
                Map<Integer, List<String>> selectType = new HashMap<>();
                // store data in different hashmap based on direction and protocol
                if (data[0].equals("inbound") && data[1].equals("tcp")) {
                    selectType = this.typeOne;
                } else if (data[0].equals("outbound") && data[1].equals("tcp")) {
                    selectType = this.typeTwo;
                } else if (data[0].equals("inbound") && data[1].equals("udp")) {
                    selectType = this.typeThree;
                } else if (data[0].equals("outbound") && data[1].equals("udp")) {
                    selectType = this.typeFour;
                }
                // process ip & ip range
                int index = data[3].indexOf("-");
                if (index != -1) {
                    String startip = data[3].substring(0, index);
                    String endip = data[3].substring(index+1);
                    ipRangeMap.add(startip);
                    ipRangeMap.add(endip);
                } else {
                    ipRangeMap.add(data[3]);
                }
                // process port & port range
                if (data[2].contains("-")) {
                    String[] portRange = data[2].split("-");
                    int start = Integer.parseInt(portRange[0]);
                    int end = Integer.parseInt(portRange[1]);
                    for (int i = 0; i < (end - start + 1); i ++) {
                        selectType.put((start + i), ipRangeMap);
                    }
                } else {
                    selectType.put(Integer.parseInt(data[2]), ipRangeMap);
                }
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException exception) {
            System.out.println(exception.toString());
        }
    }

    public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
        if (direction == null || protocol == null || port < 1 || port > 65535 || ip_address == null) {
            throw new Error("incorrect input");
        }
        if (direction == "inbound") {
            if (protocol == "tcp") {
                return checkPortIp(port, ip_address, typeOne);
            } else if (protocol == "udp") {
                return checkPortIp(port, ip_address, typeThree);
            }
        } else if (direction == "outbound") {
            if (protocol == "tcp") {
                return checkPortIp(port, ip_address, typeTwo);
            } else if (protocol == "udp") {
                return checkPortIp(port, ip_address, typeFour);
            }
        }
        return false;
    }

    // helper method used in accept_packet to match port and ip address in rules
    public boolean checkPortIp (int port, String ipAddress, Map<Integer,List<String>> type) {
        if (type.containsKey(port)) {
            if (type.get(port).size() == 1 && type.get(port).get(0).equals(ipAddress)) {
                return true;
            } else if (type.get(port).size() == 2) {
                long lowIp = ipToLong(type.get(port).get(0));
                long highIp = ipToLong(type.get(port).get(1));
                long currIp = ipToLong(ipAddress);
                return (currIp >= lowIp && currIp <= highIp);
            }
        }
        return false;
    }

    // helper method to convert ip into long for comparison
    public static long ipToLong(String ipString) {
        String[] ipArray = ipString.split("\\.");
        long result = 0;
        for (int i = 0; i < ipArray.length; i++) {
            int power = 3 - i;
            int ip = Integer.parseInt(ipArray[i]);
            result += ip * Math.pow(256, power);
	    }
        return result;
    }

    // for testing purposes
    public static void main(String[] args) {
        Firewall fw = new Firewall("test.csv");
        // Rule 1
        // true
        System.out.println(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
        // false
        System.out.println(fw.accept_packet("inbound", "tcp", 60, "192.168.1.2"));
        
        // Rule 2
        // true
        System.out.println(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11"));
        // true
        System.out.println(fw.accept_packet("outbound", "tcp", 20000, "192.168.10.11"));
        // true
        System.out.println(fw.accept_packet("outbound", "tcp", 11000, "192.168.10.11"));
        // false
        System.out.println(fw.accept_packet("outbound", "tcp", 31000, "192.168.10.11"));
        // false
        System.out.println(fw.accept_packet("outbound", "tcp", 10010, "192.168.10.1"));
        // false
        System.out.println(fw.accept_packet("outbound", "tcp", 10010, "192.168.1.2"));

        // Rule 3
        // true
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.1.1"));
        // true
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.2.5"));
        // true
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.1.5"));
        // false
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.5.2"));

        // Rule 4
        // true
        System.out.println(fw.accept_packet("outbound", "udp", 1000, "52.12.48.92"));
        // true
        System.out.println(fw.accept_packet("outbound", "udp", 2000, "52.12.48.92"));
        // true
        System.out.println(fw.accept_packet("outbound", "udp", 1500, "52.12.48.92"));
        // false
        System.out.println(fw.accept_packet("outbound", "udp", 3000, "52.12.48.92"));

        // Bad inputs
        // false
        System.out.println(fw.accept_packet("", "udp", 3000, "52.12.48.92"));
        // false
        System.out.println(fw.accept_packet("inbound", "", 3000, "52.12.48.92"));
        // false
        System.out.println(fw.accept_packet("outbound", "udp", 70000, "52.12.48.92"));
        // false
        System.out.println(fw.accept_packet("outbound", "udp", 70000, "52.12.48.356"));
    }
}
