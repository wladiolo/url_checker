#!/usr/bin/python3

# url_checker simply check a url or a list of url.
# Checks are specified through rules.
# It takeas in input a url (and optionally a port and a path)
# and it tryies to get the address based on the rules
# E.g. url = www.url_checker.kkk
# rule 1: verify if exist https://www.url_checker.kkk:9443/path/to/file
# url_checker.py -u www.url_checker.com -p 9443 -t /path/to/file
# url_checker tries to get the url and report on the result, following
# every type of redirect
# see rules.txt for some example rules

# Options
# -f <file>: a file with a list of url and optionally port and path semicolon separated (url;port;path)
# -u <url>: url to test
# -p <port>: port to test
# -t <path>: path to test
# -o <output>: output file

import requests
import sys
import re
import time
import socket
import getopt

# main program
def main(argv):
    t_out = 30 # timeout
    tls_ver = False # check certificate 
    
    # check the presence of rules.txt
    try:
        f_rules = open("rules.txt","r")
    except Exception as ex:
        print("[!] " + str(ex))
        sys.exit(2)

    inputfile,outputfile,url,port,path = argument_parsing(argv)

    print("[i] Input file: " + inputfile)
    print("[i] Output file: " + outputfile)
    print("[i] Url: " + url)
    print("[i] Port: " + port)
    print("[i] Path: " + path)
    
    # additional output files
    filelog = outputfile + ".log"
    filedns = outputfile + ".dns"
    f_out = open(outputfile,"w")
    f_log = open(filelog,"w")
    f_dns = open(filedns,"w")
  
    f_dns.write("url;IP\n")
    f_out.write("url;");

    if (inputfile == ""):
        # no input file, it will analyze the url
        # resolve IP
        find_ip(url,f_dns,f_log)
        #test url
        test_url(url,port,path,t_out,tls_ver,f_rules,f_out,f_log,True)
        f_out.write("\n")
    else:
        # an input file is passed as arguments. It parses the file an check every url
        # additional output files
        f_in = open(inputfile,"r")
        count_run = 0
        for ln in f_in.readlines():
            line = ln.rstrip("\r")
            # parse the line
            url,port,path=line.split(";")

            # if url ends with /, it removes it
            m2 = re.search('\/$',url)
            if m2 : url = re.sub('\/$','',url)
            
            # Resolve IP
            find_ip(url,f_dns,f_log)
            # test url
            if count_run == 0 :
                test_url(url,port,path,t_out,tls_ver,f_rules,f_out,f_log,True)
                count_run = 1
            else:
                test_url(url,port,path,t_out,tls_ver,f_rules,f_out,f_log,False)
            f_out.write("\n")
                  
        f_in.close()

    # close all files
    f_out.close()
    f_log.close()
    f_dns.close()
    f_rules.close()
        
# argument parsing
def argument_parsing(argv):
    # arguments to parse
    inputfile = ""
    url = ""
    port = ""
    path = ""
    outputfile = ""
    
    # parsing 
    try:
        opts, args = getopt.getopt(argv,"hf:u:p:t:o:")
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt in ("-f"):
            inputfile = arg
        elif opt in ("-o"):
            outputfile = arg
        elif opt in ("-u"):
            url = arg
        elif opt in ("-p"):
            port = arg
        elif opt in ("-t"):
            path = arg
        
    # check of mandatory arguments
    # if f is empty, then u is mandatory
    if (inputfile == "" and url == ""):
        print_help()
        sys.exit(2)
    # if f is not empty, u will be ignored
    if (inputfile != "" and url != ""):
        print("[i] \"" + url + "\" will be ignored.")
    # if o is empty, outputfile will be "out-" concatenated to inputfile
    if (outputfile == "" and inputfile != ""):
        outputfile = "out-" + inputfile
    # if o and f is empty, default name will be used
    if (outputfile == "" and inputfile == ""):
        outputfile = "output"

    return inputfile,outputfile,url,port,path

# just print the help when needed
def print_help():
    print("script_name [-f|-u] [OTHER OPTIONS]")
    print("OPTIONS:")
    print("-f file    input file with url, port and path (semicolon separeted) to analyze")
    print("           NOTE: if both file and url are passed, only file will be considered")
    print("-u url     url to analyze (mandatory if -f is not present)")
    print("-p port    port to analyze")
    print("-t path    path to analyze")
    print("-o file    output file with analysis")

# it checks the url: check redirects and auto refresh
def check_url(url,t_out,tls_ver,fileout,filelog):
    check_ex = 0
    while url:
        url = url.strip("\n")
        # it tries to open the url
        try:
            out = requests.get(url,timeout=t_out,verify=tls_ver)
        except Exception as ex:
            # something went wrong ...
            print("[!] " + str(ex))
            filelog.write("[!] " + str(ex) + "\n")
            fileout.write("error;")
            check_ex = 1
            url = ""
        else:
            # everything ok
            if out.history:
                # it analizes the story of redirects..
                for resp in out.history:
                    print("[i] Response: " + str(resp.status_code) + " (" + resp.url + ")")
                    filelog.write("[i] " + str(resp.status_code) + " " + str(resp.url) + "\n")
            
            print("[i] Response: " + str(out.status_code) + " (" + out.url + ")")
            
            # if out.url ends with / it removes it
            out_url = out.url
            m2 = re.search('\/$',out_url)
            if m2 :
                out_url = re.sub('\/$','',out_url)

            if out.status_code == 200:
                # it verifies if in the page is there a refresh to another page
                content_list = str(out.text).split("\n")
                for l in content_list:
                    m=re.search('meta http-equiv="refresh".*url\=([\w\W]+)\"',str(l).lower())
                    if m :
                        # there is a refresh. it extracts the url (no change on the case)
                        m2 = re.search('(url|URL)\=([\w\W]+)\"',str(l))
                        url_temp = m2.group(2)
                        
                        # if url_temp ends with / it removes it
                        m2 = re.search('\/$',url_temp)
                        if m2 :
                            url_temp = re.sub('\/$','',url_temp)

                        # check if url_temp statrs with http or https
                        m2=re.search('(^http|^https)',url_temp)
                        if m2 :
                            # it is a complete url, it uses it
                            url = url_temp
                        else :
                            # it is an incomplete url: it builds it
                            # if it starts with / it removes it
                            m3 = re.search('^\/',url_temp)
                            if m3 :
                                url_temp = re.sub('^\/','',url_temp)                            
                            
                            # it builds the complete url
                            url = out_url + "/" + url_temp
                            
                        print("[i] auto refresh to: " + str(url) + "\n")
                        filelog.write("[i] auto refresh to: " + str(url) + "\n")
                        break
                    else:
                        url = ""
            else:
                url = ""
    
    if check_ex == 0:
        # if no exception occurred it saves the information
        filelog.write("[i] " + str(out.status_code) + " " + str(out.url) + "\n")
        m=re.search('((?:http|https)://[\w\-\.\_\:]+).*',str(out.url))
        #fileout.write(m.group(1) + ";")
        #fileout.write(out.url + ";" + str(out.status_code) + ";")
        fileout.write(out.url + ";")
   
    return 0

# it resolves the IP address
def find_ip(url,f_dns,f_log):
    try:
        ip_addr = socket.gethostbyname(url)
    except Exception as ex:
        # something  went wrong...
        print("[!] " + str(ex))
        f_log.write("[!] " + str(ex) + "\n")
    else:
        # everything ok!
        f_dns.write(url + ";" + ip_addr + ";\n")
        print("[i] " + url + " resolve to " + ip_addr)

# it tests the url against the rules 
def test_url(url,port,path,t_out,tls_ver,f_rules,f_out,f_log,heading):
    url2test = ""
    if heading :
        for l in f_rules.readlines():
            line = l.strip()

            if line != "" :
                if (line.find("#") == -1 and line.find("@") != -1) :
                    # is there some checks in the rule
                    part1,part2 = line.split("@")
                    f_out.write(part1 + ";")
                elif (line.find("#") == -1 and line.find("@") == -1):
                    # there is no checks in the rule
                    f_out.write(line + ";")
        f_out.write("\n")
        
    f_out.write(url + "\;")
    f_rules.seek(0)
    for l in f_rules.readlines():
        line = l.strip()

        url2test = build_url2test(line,url,port,path)

        if url2test != "" :
            url2test = url2test.strip("\n")
            #print("[i] Rule: " + line + " >> URL to test: " + url2test)

            # logging orario
            t=time.localtime()
            print("[i] "+ str(t.tm_year)+"-"+str(t.tm_mon)+"-"+str(t.tm_mday)+" "+str(t.tm_hour)+":"+str(t.tm_min)+":"+str(t.tm_sec)+" "+str(t.tm_zone) +" >> Rule: " + line)
            print("[i] Request: " + url2test)
            f_log.write("[i] " + str(t.tm_year)+"-"+str(t.tm_mon)+"-"+str(t.tm_mday)+" "+str(t.tm_hour)+":"+str(t.tm_min)+":"+str(t.tm_sec)+" "+str(t.tm_zone) +" --> " + url2test + "\n")

            check_url(url2test,t_out,tls_ver,f_out,f_log)

def build_url2test(line,url,port,path):
    commands = []
    checks = []
    rule = ""
    u2t = ""
    # check if it's not a comment line
    if line != "" :
        if (line.find("#") == -1 and line.find("@") != -1) :
            # is there some checks in the rule
            part1,part2 = line.split("@")
            commands = part1.split("|")
            checks = part2.split("|")
            rule = "ok"
        elif (line.find("#") == -1 and line.find("@") == -1):
            # there is no checks in the rule
            commands = line.split("|")
            rule = "ok"
                                                                                                                                                                                    
        # it builds the url to test
        if rule == "ok" :
            # it puts the protocol (e.g. http)
            if commands[0] != "" :
                u2t = u2t + commands[0] + "://"
            else:
                print("[!] Error in rule: " + line)
                sys.exit(2)                                                                                                                                                                                                                                                                                                                                              
            # it puts the url
            if commands[1] == "u" :
                u2t = u2t + url
            else:
                print("[!] Error in rule: " + line)
        
            # it puts the port specified in the file or in p option or
            # the port specified in the rule
            if commands[2] == "" :
                u2t = u2t
            elif commands[2] == "p" and port != "" :
                u2t = u2t + ":" + port
            elif commands[2] == "p" and port == "" :
                u2t = u2t
            elif commands[2] != "p":
                u2t = u2t + ":" + commands[2]
            
            # it puts the path
            if commands[3] == "" :
                u2t = u2t
            elif commands[3] == "t" and path != "" :
                u2t = u2t + path
            elif commands[3] == "t" and path == "" :
                u2t = u2t
        
    return u2t

if __name__ == "__main__":
    main(sys.argv[1:])


