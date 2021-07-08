import re, os, subprocess, time, re, socket
from urllib.request import Request, urlopen

class Parser:

    def __init__(self):
        #Change constructor variable to the text file which holds the header information
        self.hFile = "HEADER_FILE_NAME.txt"
        self.outFile = "HEADER_REPORT_FILE_NAME.txt"

    #Function to open header text file and extract information to list
    def openHeader(self, headFile):
        x = []
        #Appending header line to list
        with open(headFile, "r") as head:
            for i in head:
                x.append(i.split("\n"))

        #Cleaning header sublists
        x = [[j.strip() for j in i if j!=''] for i in x if i!=None]
        
        return x
    def permitted(self, headList):
        #Find all strings that contain 'designates' as an identifier for permitted or non permitted senders
        permit = [[j for j in i if "designates" in j] for i in headList]

        #Removing all empty sublists
        permit = list(filter(None, permit))

        return permit
        
    def ipAddresses(self, headList):
        #Find all IP addresses in sublists
        ipAddresses = [re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                                  str(j)) for i in headList for j in i]

        #Removing all empty sublists
        ipAddresses = list(filter(None, ipAddresses))

        return ipAddresses
    
    def fullyQualifiedDomain(self, headList):
        #Find all fully qualified domains in sublists using regular expressions
        fullDomain = [re.findall("((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))",
                                 str(j)) for i in headList for j in i]
        
        #Removing all empty sublists
        fullDomain = list(filter(None, fullDomain))

        return fullDomain

    def topLevelDomain(self, headList):
        #Find all top level domains in sublists using regular expressions
        topLevel = [re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}',
                               str(j)) for i in headList for j in i]

        #Removing all empty sublists
        topLevel = list(filter(None, topLevel))

        return topLevel

    def emailAddresses(self, headList):
        #Find all email addresses in header using regular expressions
        email = [re.findall(r'[\w\.-]+@[\w\.-]+', str(j)) for i in headList for j in i]
        
        #Removing all empty sublists
        email = list(filter(None, email))

        return email

    def replyTo(self, headList):
        #Find all strings that contain 'Reply'
        reply = [[j for j in i if "Reply" in j] for i in headList]

        #Removing all empty sublists
        reply = list(filter(None, reply))

        return reply

    #Primary function which generated the potential Phishing email report
    def writeParsedHeader(self, ip, ipParse, domain, topLevel, emailAddr, replyTo, permitted):
        flag = ""
        x = len(ip)
        try:
            #Writing parsed information to output file
            with open(self.outFile, "w") as parsed:
                parsed.write("***Potential Phishing Email Report***\n\n")
                if len(ip)>1:
                    parsed.write("---IP ADDRESS PATH---\n%d IP addresses discovered\n\n" % (len(ip)))
                else:
                    parsed.write("---IP ADDRESSES---\nNo IP addresses discovered\n\n")
                for item in ip:
                    if x == len(ip):
                        parsed.write(str("[%d - Destination IP] " % (x))+
                                     "".join(i for i in str(item) if i not in "[]'\n")+"\n")
                    elif x == 1:
                        parsed.write(str("[%d - Source IP] " % (x))+
                                     "".join(i for i in str(item) if i not in "[]'\n")+"\n")
                    else:
                        #Writing list to output file and removing opening and trailing list identifiers
                        parsed.write(str("[%d] " % (x))+"".join(i for i in str(item) if i not in "[]'\n")+"\n")
                    x = x-1
                    
                #parse.write(str("\n---PUBLIC IP ADDRESSES---\n")+str(self.generateOutput(ipParse[0])))

                """parse.write("\n---PUBLIC IP ADDRESSES---\n",
                            str(self.generateOutput(ipParse[0])),
                            "\n---FULLY QUALIFIED DOMAINS---\n%d fully qualified domains discovered\n\n" % (len(domain)),
                            str(self.generateOutput(domain)),
                            "\n---TOP LEVEL DOMAINS---\n%d top level domains discovered\n\n" % (len(topLevel)),
                            str(self.generateOutput(domain)),
                            "\n---E-MAIL ADDRESSES---\n%d E-Mail addresses discovered\n\n" % (len(emailAddr)),
                            str(self.generateOutput(emailAddr)),
                            "\n---REPLY TO---\n%d reply to string\n\n" % (len(replyTo),
                            str(self.generateOutput(replyTo)),
                            "\n---PERMITTED---\n%d instances listed which designates source IP send permission\n\n" % (len(permitted)),
                            str(self.generateOutput(permitted))))"""                            
                            
                #Writing parsed Public IP Addresses    
                parsed.write("\n---PUBLIC IP ADDRESSES---\n")
                parsed.write(self.generateOutput(ipParse[0]))                    
                #Writing parsed Fully-Qualified Domains
                parsed.write("\n---FULLY QUALIFIED DOMAINS---\n%d fully qualified domains discovered\n\n" % (len(domain)))
                parsed.write(self.generateOutput(domain))                    
                #Writing parsed Top-Level Domains
                parsed.write("\n---TOP LEVEL DOMAINS---\n%d top level domains discovered\n\n" % (len(topLevel)))
                parsed.write(self.generateOutput(topLevel))                    
                #Writing parsed Email Addresses
                parsed.write("\n---E-MAIL ADDRESSES---\n%d E-Mail addresses discovered\n\n" % (len(emailAddr)))
                parsed.write(self.generateOutput(emailAddr))
                #Writing parsed Reply to Addresses
                parsed.write("\n---REPLY TO---\n%d reply to string\n\n" % (len(replyTo)))
                parsed.write(self.generateOutput(replyTo))
                #Writing whether sender has been designated as permitted
                parsed.write("\n---PERMITTED---\n%d instances listed which designates source IP send permission\n\n" %
                             (len(permitted)))
                parsed.write(self.generateOutput(permitted))
                
            parsed.close()
            flag = "Output file has been created.."
            #Open output file in window
            os.startfile(self.outFile)
        except Exception as ex:
            flag = ("Encountered error when writing output file.\n%s" % (ex))

    def generateOutput(self, prop):
        propString = ""
        for item in prop:
            propString = propString + (''.join(i for i in str(item) if i not in "[]',\n")+ "\n")

        return propString
    
    #Function for test purposes
    def testing(self, headList):        
        testList = [j for i in headList for j in i]
        testList = [re.findall(r'[^@]+@[^@]+\.[^@]+', str(j)) for j in testList]
        testList = list(filter(None, testList))
        
        return testList
    
    #In Testing
    def grabOutput(self):
        i = "www.google.co.uk"
        proc = subprocess.Popen('nslookup %s' % (i), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        commandOutput = proc.stdout.read()
        #time.sleep(5)
        return commandOutput

    #In Progress
    def queryCommand(self, string):
        strings = ["\r", "\n"]
        toQuery = []
        commandOutput = []
        for item in string:
            toQuery.append((''.join(i for i in str(item) if i not in "[]'\n")))
            
        """try:
            for i in toQuery[0:3]:
                proc = subprocess.Popen('nslookup %s' % (i), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                commandOutput.append(proc.stdout.read())
                time.sleep(5)
        except Exception as e:
            pass
        #commandOutput = [i.strip(b"\r\n") for i in commandOutput]"""
        return commandOutput

    def ipParse(self, ip):
        #Private IP identifiers
        PrivIp = ["10.", "192.", "172.", "127."]

        #Generating seperate lists of public and private IPs
        public = [[j for j in i if j[0:3]!= PrivIp[0] and j[0:4] != PrivIp[1]
                   and j[0:4] != PrivIp[2] and j[0:4] != PrivIp[3]] for i in ip]
        
        private = [[j for j in i if j[0:3] == PrivIp[0] and j[0:4] == PrivIp[1]
                    and j[0:4] == PrivIp[2] and j[0:4] == PrivIp[3]] for i in ip]

        public = list(filter(None, public))
        private = list(filter(None, private))
        
        return public, private
    
    #WORK IN PROGRESS TO GEOLOCATE IP ADDRESS
    def locateIP(self, ipAddresses):

        for i in range(0, len(ipAddresses)):
            ips = ipAddresses[i]
            s = ""
            ip = "".join(ipAddresses[i])
        
            req = Request("http://api.hostip.info/get_html.php?ip=" + ip + "&position=true",
                          headers={'User-Agent': 'Mozilla/5.0'})
            webpage = urlopen(req).read()
            print(webpage)
            time.sleep(5)

        
        #locate = urllib.urlopen("http://api.hostip.info/get_html.php?ip=" + ip + "&position=true")
                
    def main(self):
        #Open header file
        head = self.openHeader(self.hFile)
        head = [[x.split() for x in y] for y in head]
        
        #Extract ip addresses and fully qualified domains
        ip = self.ipAddresses(head)
        fulldomain = self.fullyQualifiedDomain(head)
        topLevel = self.topLevelDomain(head)
        emailAddr = self.emailAddresses(head)
        repto = self.replyTo(head)
        ipParse = self.ipParse(ip)
        permit = self.permitted(head)

        #-Geolocate IP
        #self.locateIP(ipParse)
        
        #-Testing purposes-   
        #print("%s\n%s" % (ip, domain))

        #Write information to output file
        print(self.writeParsedHeader(ip, ipParse, fulldomain, topLevel, emailAddr, repto, permit))
        #print(self.queryCommand(ip))
        #print(self.testTwo())

if __name__ == "__main__":
    parse = Parser()
    parse.main()
        



