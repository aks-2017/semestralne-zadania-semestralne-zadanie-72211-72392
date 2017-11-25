#!/usr/bin/env python

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import RemoteController
from mininet.term import makeTerm
from time import sleep
import subprocess

if '__main__' == __name__:
    net = Mininet(controller=RemoteController, link=TCLink)

    # set delay to communication with controller
    subprocess.Popen(["tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "13ms"])
    c0 = net.addController('c0', port=6633)

    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')
    s6 = net.addSwitch('s6', protocols='OpenFlow13')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    h5 = net.addHost('h5')
    h6 = net.addHost('h6')

    net.addLink(s1, h1, bw=100, delay='8ms')
    net.addLink(s2, h2, bw=100, delay='8ms')
    net.addLink(s3, h3, bw=100, delay='8ms')
    net.addLink(s4, h4, bw=100, delay='8ms')
    net.addLink(s5, h5, bw=100, delay='8ms')
    net.addLink(s6, h6, bw=100, delay='8ms')

    net.addLink(s1, s2, bw=100, delay='8ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='8ms')
    net.addLink(s4, s5, bw=100, delay='8ms')
    net.addLink(s5, s6, bw=100, delay='8ms')
    net.addLink(s6, s1, bw=100, delay='8ms')

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
    s6.start([c0])

    print("starting mininet")
    net.start()
    # wait to set up all
    sleep(10)
    # start the controller
    print("starting controller")
    c0_process = subprocess.Popen(["ryu-manager", "--observe-links", "../ryu/simple_switch_nx.py"])
    sleep(15)

    # start the traffic
    print("starting the traffic")
    h1.cmd('iperf -s &')
    h4.cmd('iperf -c 10.0.0.1 -t 100 &')

    # start the monitoring
    print("starting the monitoring")
    s4.cmd("bwm-ng -o csv -c 80 -T rate -I s4-eth2 -t 1000 > logs/S4toS3.csv &")
    s4.cmd("bwm-ng -o csv -c 80 -T rate -I s4-eth3 -t 1000 > logs/S4toS5.csv &")
    h4.cmd("bwm-ng -o csv -c 80 -T rate -I h4-eth0 -t 1000 > logs/host.csv &")
    sleep(10)
    net.configLinkStatus("s3", "s4", "down")
    sleep(20)
    net.configLinkStatus("s3", "s4", "up")
    sleep(20)
    net.configLinkStatus("s3", "s4", "down")
    net.configLinkStatus("s2", "s3", "down")
    sleep(30)

    # shuting down the controller
    c0_process.terminate()
    sleep(3)
    if c0_process.poll() is None:
        print("kill kill")
        c0_process.kill()
    net.stop()
