import os, sys, time, socket, struct, fcntl, re
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import pcap
from itertools import count
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

class SignalStrength:
    def __init__(self, iface=None, mac=None):
        self.monitor_on = False
        self.mon_iface = self.get_mon_iface(iface)
        self.iface = self.mon_iface
        self.mac = mac
        self.pwr = 0
        self.index = count()
        self.exit = False
        self.x_val = []
        self.y_val = []

    def get_mon_iface(self, iface):
        if iface:
            if self.check_monitor(iface):
                self.monitor_on = True
                return iface

    def check_monitor(self, iface):
        try:
            proc = Popen(['iwconfig', iface], stdout=PIPE, stderr=PIPE)
            data =  proc.communicate()
            if "Mode:Monitor" in data[0].decode():
                return True
            elif "No such device" in data[1].decode():
                print("Interface not found")
                return False
            print("Interface is not in mode monitor")
            self.start_mon_mode(iface)
            return True
        except OSError:
            print('Could not execute "iwconfig"')
            return False

    def start_mon_mode(self, interface):
        print(f'Starting monitor mode off {interface}')
        try:
            os.system('ifconfig %s down' % interface)
            os.system('iwconfig %s mode monitor' % interface)
            os.system('ifconfig %s up' % interface)
            return interface
        except Exception:
            print('Could not start monitor mode')
            self.exit = True

    def animate(self,i):
        self.x_val.append(next(self.index))
        self.y_val.append(self.pwr)
        plt.cla()
        plt.title(self.mac)
        plt.plot(self.x_val, self.y_val)

    def chartGUI(self):
        plt.style.use('fivethirtyeight')
        ani = FuncAnimation(plt.gcf(), self.animate, interval = 1000)

        plt.tight_layout()
        plt.show()

    def signal(self):
        sniffer = pcap.pcap(name=self.mon_iface, promisc=True, immediate=True, timeout_ms=50)
        for ts, pkt in sniffer:
            ta_h = pkt[0x22:0x22+6].hex()
            ta = ':'.join(ta_h[i:i + 2] for i in range(0, 12, 2))
            if ta == self.mac:
                pwr = struct.unpack("b",struct.pack("B",pkt[0x12]))[0]
                self.pwr = pwr


    def run(self):
        th = Thread(target=self.signal)
        th.daemon = True
        th.start()

        self.chartGUI()

if __name__ == "__main__":
    if os.geteuid():
        print("Please run as root")
    else:

        if len(sys.argv) < 2:
            print("Usage: sudo python3 signal-strength.py <interface> <mac>")
            print("Sample : sudo python3 signal-strength.py mon0 00:11:22:33:44:55")
            sys.exit()

        iface = sys.argv[1]
        mac = sys.argv[2].lower()

        if iface != "" :
            sn = SignalStrength(iface=iface,mac=mac)
            sn.run()
