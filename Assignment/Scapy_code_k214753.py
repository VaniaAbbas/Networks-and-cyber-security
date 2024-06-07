import re
from scapy.all import sniff, IP, TCP, Raw
import logging
import configparser

class Matcher:
    def __init__(self, config_file="config.ini"):
        self.load_config(config_file)
        self.setup_logging()

    def load_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)

        self.website_patterns = [re.compile(pattern) for pattern in config.get("Detection", "WebsitePatterns").split(",")]

        self.firewall_enabled = config.getboolean("Firewall", "Enabled")

    def setup_logging(self):
        logging.basicConfig(filename="network_activity.log", level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    def detect_attack(self, packet):
        if IP in packet and TCP in packet:
            self.log_network_activity(packet.summary())

            try:
                payload = packet[Raw].load.decode('utf-8', 'ignore')
            except IndexError:
                payload = ""

            for pattern in self.website_patterns:
                if pattern.search(payload):
                    print(f"Website matching pattern {pattern.pattern} detected!")
                    self.log_alert(f"Website matching pattern {pattern.pattern} detected!")
                    self.respond_to_attack(packet)

    def respond_to_attack(self, packet):

        if self.firewall_enabled:
            self.block_ip(packet[IP].src)

    def block_ip(self, ip_address):
        logging.warning(f"Blocking IP Address {ip_address} using iptables.")

    def log_alert(self, message):
        logging.warning(f"ALERT: {message}")
        with open("alert_generated.log", "a") as alert_file:
            alert_file.write(f"{message}\n")

    def log_network_activity(self, activity):
        logging.info(activity)

    def start_sniffing(self):
        try:
            print("Starting the IDS with Firewall...")
            sniff(filter="tcp", prn=self.detect_attack, store=0)
        except KeyboardInterrupt:
            self.log_info("Stopping the IDS with Firewall.")

if __name__ == "__main__":
    ids_with_firewall = Matcher()
    ids_with_firewall.start_sniffing()
