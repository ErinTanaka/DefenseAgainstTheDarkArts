import json, sys, getopt, os
# from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.naive_bayes import GaussianNB
import numpy as np
from sklearn.neural_network import MLPClassifier


def usage():
    print("Usage: %s --trainfile=[filename] --testfile=[filename]" % sys.argv[0])
    sys.exit()

def get_data(featurenames, urldata):
    table=[]
    for record in urldata:
        tmp=[]
        for name in featurenames:
            if name=="ips" or name=="domain_tokens" or name == "path_tokens":
                if record[name] == None:
                    tmp.append(0)
                else:
                    tmp.append(len(record[name]))
            else:
                tmp.append(record[name])
        table.append(tmp)
    return table
def build_feature_set(urldata):
    featurenames = ["domain_age_days", "ips", "alexa_rank", "file_extension", "query","domain_tokens", "num_path_tokens", "default_port"]
    featset = []
    for feat in featurenames:
        entry=[]
        for line in urldata:
            if feat == "ips" or feat =="domain_tokens":
                if line[feat] == None:
                    entry.append(0)
                else:
                    entry.append(len(line[feat]))
            else:
                entry.append(line[feat])
        featset.append(entry)
    return featset   

def main(argv):

    trainfile=''
    testfile=''
    myopts, args = getopt.getopt(sys.argv[1:], "", ["trainfile=", "testfile="])
    for o, a in myopts:
        print a
        if o in ('--trainfile'):
            trainfile=a
        elif o in ('--testfile'):
            testfile=a
        else:
            usage()

    if len(trainfile) == 0 or len(testfile)==0:
        usage()

    corpus = open(trainfile)
    trainurldata = json.load(corpus, encoding="latin1")
    corpus.close()
    corpus = open(testfile)
    testurldata = json.load(corpus, encoding="latin1")
    corpus.close()
    classifications = []
    for record in trainurldata:
        classifications.append(record["malicious_url"])
    #preprocessing
    # featurenames = ["domain_age_days", "ips", "alexa_rank", "file_extension", "query","domain_tokens", "path_tokens", "default_port"]
    trainfeats=build_feature_set(trainurldata)
    testfeats=build_feature_set(testurldata)
    print len(trainfeats), len(trainfeats[0])
    trainfeats = np.rot90(np.asarray(trainfeats))
    testfeats = np.rot90(np.asarray(testfeats))
    enc = OneHotEncoder(handle_unknown='ignore')
    enc_train = enc.fit_transform(trainfeats)
    enc_test = enc.transform(testfeats)
    # print enc_train.shape
    NN = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    NN.fit(enc_train,classifications)
    trainpredictions = NN.predict(enc_train)
    testpredictions = NN.predict(enc_test)
    for i in range  (0,len(testurldata)):
        print testurldata[i]["url"], testpredictions[i]
    badurls = testpredictions.sum()
    print "accuracy of model on training data: ", NN.score(enc_train, classifications)
    print "number of malicious urls", badurls, "out of ", testpredictions.size



if __name__ == "__main__":
    main(sys.argv[1:])
