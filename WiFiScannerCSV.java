import java.io.*;
import java.net.InetAddress;
import java.util.*;
import java.util.regex.*;

public class WiFiScannerCSV {

    public static void main(String[] args) {
        String ssid = getSSID();
        System.out.println("Connected WiFi SSID: " + (ssid != null ? ssid : "Unknown"));

        String ip = getLocalIPAddress();
        String subnet = getSubnetFromIP(ip);
        if (subnet == null) {
            System.out.println("Unable to detect subnet.");
            return;
        }

        System.out.println("\nScanning Network: " + subnet + "0/24");

        pingAllDevices(subnet);
        List<Device> devices = getConnectedDevices();

        System.out.println("\nDevices connected to WiFi \"" + ssid + "\":");
        for (Device device : devices) {
            System.out.println("IP: " + device.ip + " | MAC: " + device.mac);
        }

        exportToCSV(devices, ssid);
    }

    private static String getSSID() {
        try {
            Process p = Runtime.getRuntime().exec("netsh wlan show interfaces");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().startsWith("SSID") && !line.contains("BSSID")) {
                    return line.split(":", 2)[1].trim();
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private static String getLocalIPAddress() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    private static String getSubnetFromIP(String ip) {
        if (ip == null || !ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return null;
        return ip.substring(0, ip.lastIndexOf('.') + 1);
    }

    private static void pingAllDevices(String subnet) {
        for (int i = 1; i < 255; i++) {
            final String ip = subnet + i;
            new Thread(() -> {
                try {
                    Process p = Runtime.getRuntime().exec("ping -n 1 -w 100 " + ip);
                    p.waitFor();
                } catch (Exception ignored) {}
            }).start();
        }
        try {
            Thread.sleep(8000); // Wait for pings
        } catch (InterruptedException ignored) {}
    }

    private static List<Device> getConnectedDevices() {
        List<Device> deviceList = new ArrayList<>();
        try {
            Process p = Runtime.getRuntime().exec("arp -a");
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            Pattern ipPattern = Pattern.compile(
                "(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([\\w-]+)\\s+(dynamic|static)"
            );

            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = ipPattern.matcher(line);
                if (matcher.find()) {
                    String ip = matcher.group(1);
                    String mac = matcher.group(2);
                    deviceList.add(new Device(ip, mac));
                }
            }
        } catch (Exception e) {
            System.out.println("Failed to read ARP table.");
        }
        return deviceList;
    }

    private static void exportToCSV(List<Device> devices, String ssid) {
        String fileName = "wifi_devices.csv";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName))) {
            writer.write("WiFi SSID:," + ssid + "\n");
            writer.write("IP Address,MAC Address\n");
            for (Device device : devices) {
                writer.write(device.ip + "," + device.mac + "\n");
            }
            System.out.println("\nCSV exported successfully to: " + fileName);
        } catch (IOException e) {
            System.out.println("Failed to write CSV: " + e.getMessage());
        }
    }

    static class Device {
        String ip, mac;
        Device(String ip, String mac) {
            this.ip = ip;
            this.mac = mac;
        }
    }
}
