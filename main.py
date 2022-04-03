import nmap


class Network(object):
    def __init__(self):
        ip = input('Please Enter Default IP Address of Router: ')
        self.ip = ip

    def network_scanner(self):
        if len(self.ip) == 0:
            network = '192.188.1.1/24'
        else:
            network = self.ip + '/24'

        print("scanning please wait ------------>")

        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            print("Host\t{}".format(host))


if __name__ == "__main__":
    D = Network()
    D.network_scanner()
