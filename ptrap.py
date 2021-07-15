#!/usr/bin/env python3
import argparse
import configparser
import getpass
import logging
import os
import requests
import requests_toolbelt
import sys
import urllib3
from scapy.all import *
import ipaddress
import json
from scapy.layers.http import HTTPRequest # import HTTP packet
from scapy.layers.http import HTTP

CURRENT_DIRECTORY = os.path.dirname( os.path.abspath(__file__) )
SOURCE_DIRECTORY = os.path.join( CURRENT_DIRECTORY, 'src' )
sys.path.append( SOURCE_DIRECTORY )

# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pythopyt
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

NAME = 'ourstarter'
logger = logging.getLogger( '{}'.format(NAME) )

STARTER_HOME_DIR = '.{}'.format(NAME)
OUR_CONFIGURATION_FILE = "ourstarter.ini"
DEFAULT_CONFIGURATION = """[server]
url = https://127.0.0.1
apipath = /api/v1
verify_ssl = false"""

def make_project_homedir():
    if sys.platform == 'win32':
        user_home_dir = os.getenv( 'HOMEDRIVE', None ) + os.getenv( 'HOMEPATH', None )
    else:
        user_home_dir = os.getenv( 'HOME' )

    if not user_home_dir:
        user_home_dir = os.getcwd()

    full_path_to_project_dir = user_home_dir + os.sep + STARTER_HOME_DIR

    if not os.path.exists( full_path_to_project_dir ):
        os.mkdir( full_path_to_project_dir )
    
    return full_path_to_project_dir

def read_properties( arguments, logger ):
    our_configuration = None
    full_path_to_project_config = arguments.homedir + os.sep + arguments.configfile

    logger.info( "reading properties" )

    arguments.configfile = full_path_to_project_config
    logger.info( "full path to configuration file is {}".format(arguments.configfile) )

    if os.path.exists(full_path_to_project_config):
        our_configuration = configparser.ConfigParser()        
        our_configuration.read( full_path_to_project_config )
        logger.debug( "all read" )
        return our_configuration
    else:
        logger.info( "property file did not exist, save new default" )
        with open( full_path_to_project_config, 'w' ) as writer:
            writer.write( DEFAULT_CONFIGURATION )
            logger.debug("save") 

        our_configuration = configparser.ConfigParser()        
        our_configuration.read( full_path_to_project_config )
        logger.debug( "all read" )
        return our_configuration

def process_packet(packet, data):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        reqmethod = packet[HTTPRequest].Method.decode()
        c = {'url' : url,
            'ip' : ip,
            'reqmethod' :reqmethod}
        data['HTTPRequests'].append(c)

        
        

def parse_arguments():
    parser = argparse.ArgumentParser()

    #parser.add_argument('action', metavar='ACTION', type=str, help='Specify action for {}'.format(NAME) )

    parser.add_argument('-C', '--configfile', help="Specify an alternate project configuration filename. Default is ~/.{}/{}.ini".format(NAME,NAME))

    parser.add_argument('-H', '--homedir', help="Specify an alternate data directory. Default is ~/.{}".format(NAME) )

    parser.add_argument('-L', '--loglevel', help="Specify alternate logging level. (Default is NONE)")
    
    parser.add_argument('-O', '--outputfile', help="Specify output location")
   
    parser.add_argument('-p', '--pcapreader', help="Call on a specified .pcap file for analysis")

    parser.add_argument('-q', '--quiet', action='store_true', help="Supress logging. Default is FALSE") 

    return parser.parse_args()

#This is the Entry Point
if __name__ == "__main__":
    arguments = parse_arguments( )

    if not arguments.configfile:
        arguments.configfile = OUR_CONFIGURATION_FILE

    if not arguments.homedir:
        arguments.homedir = make_project_homedir( )

    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=arguments.loglevel)
    logger = logging.getLogger( NAME )

    if arguments.quiet:
        logger.propagate = False

    logger.info( '{} startup'.format(NAME) )
    our_properties = read_properties( arguments, logger )


#########################################################################################
#################This is the Starting point for you to work##############################


    # rdpcap comes from scapy and loads in our pcap file
    #packets = rdpcap('example.pcap')  #>>>>> this line is leftover from https://incognitjoe.github.io/reading-pcap-with-scapy.html >>>>  it is calling on a .pcap file with a very specific name. We want to call on an arugment for any .pcap file to make things more efficient.
    packets = rdpcap(arguments.pcapreader)
    data = {}

    data['IP'] = {}
    data['IP']['src.addr'] = []
    data['IP']['dst.addr'] = []

    data['DNSrequest'] = []

    data['HTTPRequests'] = []
    data['HTTPResponses'] = []

    # Let's iterate through every packet
    for packet in packets:
        # We're only interested packets with a DNS Round Robin layer
        
        
        
        if packet.haslayer(IP):
            s = packet[IP].src
            d = packet[IP].dst
            so = ipaddress.ip_address(s) #so = source output
            do = ipaddress.ip_address(d) #do = destination output
            if not so.is_private and not so.is_multicast and not so.is_loopback: # if o.is_private != True: >>>> this works too, but it's just not as efficient
                data['IP']['src.addr'].append(str(s))#, packet[IP].dst) for packet in PcapReader('file.pcap') if IP in packet)
            if not do.is_private and not do.is_multicast and not so.is_loopback: # if o.is_private != True: >>>> this works too, but it's just not as efficient
                data['IP']['dst.addr'].append(str(d))#, packet[IP].dst) for packet in PcapReader('file.pcap') if IP in packet)
            
            if packet.haslayer(DNSRR): #DNSRR = scapy object for DNS
            # If the an(swer) is a DNSRR, print the name it replied with.
                if isinstance(packet.an, DNSRR):
                    data['DNSrequest'].append(str(packet.an.rrname.decode('UTF-8'))) #This saves the DNS Requests into the data[] list
            elif packet.haslayer(HTTP):
                process_packet(packet, data)



    data['DNSrequest']=set(data['DNSrequest']) #This changes the data[] list into a "set" >>> sets DO NOT allow duplicates
    data['IP']['src.addr']=set(data['IP']['src.addr']) #This changes the data[] list into a "set" >>> sets DO NOT allow duplicates
    data['IP']['dst.addr']=set(data['IP']['dst.addr']) #This changes the data[] list into a "set" >>> sets DO NOT allow duplicates
    # print(data['IP'])
    print(data)
    #print(json.dumps(data, indent=4))