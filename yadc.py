import binascii
import time
import subprocess

from optparse import OptionParser

from scapy.all import *


conf.checkIPaddr = False


def claim_ip(iface, mac, hostname = None):
    mac_raw = binascii.unhexlify(mac.replace(':', ''))

    dhcp_discover = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=mac_raw, xid=RandInt()) / \
                    DHCP(options=[('message-type', 'discover'), 'end'])

    print('Sending DHCP discover...')
    dhcp_offer = srp1(dhcp_discover, iface=iface, verbose=0, timeout=1)

    # Extract dhcp info from offering
    candidate_ip = dhcp_offer[BOOTP].yiaddr
    src_ip = dhcp_offer[BOOTP].siaddr
    xid = dhcp_offer[BOOTP].xid

    options = [('message-type', 'request'), ('server_id', src_ip), ('requested_addr', candidate_ip), 'end']
    if hostname:
        options.append(('hostname', hostname))

    dhcp_request_frame = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr=mac_raw, xid=xid) / \
                    DHCP(options=[('message-type', 'request'), ('server_id', src_ip), \
                                  ('requested_addr', candidate_ip), 'end'])

    print('Requesting {}...'.format(candidate_ip))
    dhcp_ack = srp1(dhcp_request_frame, iface=iface, verbose=0, timeout=1)
    dhcp_offer= sniff(filter='udp port 67', iface=iface, count=1)[0]

    claimed_ip = dhcp_ack[BOOTP].yiaddr
    print('Claimed {}!'.format(claimed_ip))
    return claimed_ip


def assign_ip(ip, iface):
    print('Assign {} to {}'.format(ip, iface))
    ret = subprocess.run('ip address add {} dev {}'.format(ip, iface), shell=True)
    if ret.returncode == 0:
        print('Success!')
    else:
        print('Assignment failed')


def main():
    parser = OptionParser()
    parser.add_option('-i', '--iface', type='string', dest='iface')
    parser.add_option('-m', '--mac', type='string', dest='mac')
    parser.add_option('--hostname', type='string', dest='hostname')
    parser.add_option('-a', '--assign', action='store_true', dest='assign')

    (options, args) = parser.parse_args()

    iface = options.iface if options.iface else conf.iface
    mac = options.mac if options.mac else get_if_hwaddr(iface)

    claimed_ip = claim_ip(iface, mac, options.hostname)

    if options.assign:
        assign_ip(claimed_ip, iface)


if __name__ == '__main__':
    main()
