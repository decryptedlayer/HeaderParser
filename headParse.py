import re, os

class Parser:

    def __init__(self):
        #Change variable constructor to the text file which holds the header information
        self.hFile = "headerTest.txt"
        self.outFile = "parsedOutput.txt"

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

    def ipAddresses(self, headList):
        #Find all IP addresses in sublists
        ipAddresses = [[j for j in i if re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", j)] for i in headList]

        #Removing all empty sublists
        ipAddresses = list(filter(None, ipAddresses))

        return ipAddresses
    
    def fullyQualifiedDomain(self, headList):
        #Find all fully qualified domains in sublists using regular expressions
        fullDomain = [[j for j in i if re.findall("((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))", j)] for i in headList]

        #Removing all empty sublists
        fullDomain = list(filter(None, fullDomain))
        
        #Flatten sublists to single list
        #urls = [j for sublist in urls for j in sublist]

        if len(fullDomain) == 0:
            print("No fully qualified domains found")

        return fullDomain

    def topLevelDomain(self, headList):
        #Find all top level domains in sublists using regular expressions
        topLevel = [[j for j in i if re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', j)] for i in headList]

        #Removing all empty sublists
        topLevel = list(filter(None, topLevel))

        if len(topLevel) == 0:
            print("No fully qualified domains found")

        return topLevel

    def emailAddresses(self, headList):
        email = [[j for j in i if re.findall(r'[^@]+@[^@]+\.[^@]+', j)] for i in headList]

        #Removing all empty sublists
        email = list(filter(None, email))

        if len(email) == 0:
            print("No fully qualified domains found")

        return email
        
    def writeParsedHeader(self, ip, domain, topLevel, emailAddr):
        flag = ""        
        try:
            #Writing parsed information to output file
            with open(self.outFile, "w") as parsed:                
                parsed.write("---IP ADDRESSES---\n%d IP addresses discovered\n\n" % (len(ip)))
                for item in ip:
                    #Writing list to output file and removing opening and trailing list identifiers
                    parsed.write("".join(i for i in str(item) if i not in "[]'\n"))
                    #Writing new line to end of string write
                    parsed.write("\n")                    
                parsed.write("\n---FULLY QUALIFIED DOMAINS---\n%d fully qualified domains discovered\n\n" % (len(domain)))
                for item in domain:
                    parsed.write(''.join(i for i in str(item) if i not in "[]'\n"))
                    parsed.write("\n")
                parsed.write("\n---TOP LEVEL DOMAINS---\n%d top level domains discovered\n\n" % (len(topLevel)))
                for item in topLevel:
                    parsed.write(''.join(i for i in str(item) if i not in "[]'\n"))
                    parsed.write("\n")
                parsed.write("\n---TOP LEVEL DOMAINS---\n%d E-Mail addresses discovered\n\n" % (len(emailAddr)))
                for item in emailAddr:
                    parsed.write(''.join(i for i in str(item) if i not in "[]'\n"))
                    parsed.write("\n")
            parsed.close()
            flag = "Output file has been created.."
            #Open output file in window
            os.startfile(self.outFile)
        except Exception as ex:
            flag = ("Encountered error when writing output file.\n%s" % (ex))

        #-Testing purposes-    
        #print(flag)        
        
    def main(self):
        #Open header file
        head = self.openHeader(self.hFile)

        #Extract ip addresses and fully qualified domains
        ip = self.ipAddresses(head)
        fulldomain = self.fullyQualifiedDomain(head)
        topLevel = self.topLevelDomain(head)
        emailAddr = self.emailAddresses(head)
        
        #-Testing purposes-   
        #print("%s\n%s" % (ip, domain))

        #Write information to output file
        self.writeParsedHeader(ip, fulldomain, topLevel, emailAddr)

if __name__ == "__main__":
    parse = Parser()
    parse.main()
        



