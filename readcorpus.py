#!/usr/bin/python

import json, sys, getopt, os
#my fns
# Young domains are likely MORE malicious than old domains

# Domains which don't return IP addresses could be fast-flux domains.
#   These domains are likely to be MORE malicious. For example, how often does a
# DNS query for google.com fail?
# URLs which are listed in the Alexa top 1,000,000 are LIKELY to be LESS
#   malicious than those that are not.
# URLs with a very low Alexa rank are likely to be LESS malicious that those with
#   a high Alexa rank. This is known as "URL Prevalence"
# Another hint: 50% of the URLs in each file are malicious. Use this to help
#   validate your results.
# What about file extension. How often do you *really* download raw .exe file
#   directly from the web, instead of a software package.
# What about query string?
# How about the number of domain tokens? Path tokens?
# What port does the URL use? Do your favorite safe URLs usually use
#   non-standard ports?
# What about odd combinations?? If a URL has a keyword in it such as 'paypal',
#   but has a very young domain age and no Alexa rating, is it likely to be malicious? (Think phishing.)
def getFeatures(record):
    entry = [record["domain_age_days"], record["ips"], record["alexa_rank"], record["file_extension"], record["query"], record["domain_tokens"], record["path_tokens"], record["default_port"]]

def usage():
    print("Usage: %s --file=[filename]" % sys.argv[0])
    sys.exit()

def main(argv):

    file=''

    myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])

    for o, a in myopts:
        if o in ('-f, --file'):
            file=a
        else:
            usage()

    if len(file) == 0:
        usage()

    corpus = open(file)
    urldata = json.load(corpus, encoding="latin1")
    # all_the_shiz_nuggets=[]
    # classifications=[]
    for record in urldata:
        # tmp = rec_to_dict(rec)

    # Do something with the URL record data...
        print record["domain_age_days"]
    # classifications.append(record["malicious_url"])
    # entry = [record["domain_age_days"], record["ips"], record["alexa_rank"], record["file_extension"], record["query"], record["domain_tokens"], record["path_tokens"], record["default_port"]]
    # all_the_shiz_nuggets.append(entry)
    # print("muahaha")
    corpus.close()

if __name__ == "__main__":
    main(sys.argv[1:])
