import json, sys, getopt, os
from sklearn.impute import SimpleImputer
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
    featurenames = ["domain_age_days", "ips", "alexa_rank", "file_extension", "query","domain_tokens", "path_tokens", "default_port"]
    trainfeats=[]
    for feat in featurenames:
        tmp=[]
        for line in trainurldata:
            tmp.append(line[feat])
        trainfeats.append(tmp)
    testfeats=[]
    for feat in featurenames:
        tmp=[]
        for line in testurldata:
            tmp.append(line[feat])
        testfeats.append(tmp)
    # le = preprocessing.LabelEncoder()
    # le.fit(trainfeats[0])
    enc = OneHotEncoder(handle_unknown='ignore')
    # train_dad = enc.fit_transform(np.asarray(trainfeats[0]).reshape(1,-1))
    # test_dad = enc.transform(np.asarray(testfeats[0]).reshape(1,-1))
    enc.fit(np.asarray(trainurldata).reshape(1,-1))



    # tmp=[]
    # for retips in giantthing[1]:
    #     if retips == None:
    #         tmp.append(0)
    #     else:
    #         tmp.append(len(retips))
    # ips=le.fit_transform(tmp)
    # alexa_rank = le.fit_transform(giantthing[2])
    # file_extension = le.fit_transform(giantthing[3])
    # query = le.fit_transform(giantthing[4])
    # tmp=[]
    # for dtoks in giantthing[5]:
    #     if dtoks == None:
    #         tmp.append(0)
    #     else:
    #         tmp.append(len(dtoks))
    # domain_tokens = le.fit_transform(tmp)
    # tmp=[]
    # for ptoks in giantthing[6]:
    #     if ptoks == None:
    #         tmp.append(0)
    #     else:
    #         tmp.append(len(ptoks))
    # path_tokens = le.fit_transform(tmp)
    # default_port = le.fit_transform(giantthing[7])
    #
    # feats = zip(domain_age_days, ips, alexa_rank, file_extension, query, domain_tokens, path_tokens, default_port)
    # labels = le.fit_transform(classifications)
    # # model = GaussianNB()
    # # model.fit(feats, labels)
    # # #run model on training data
    # # trainingdataset= get_data(featurenames,urldata)
    # # training_classifications=get_classifications(urldata)
    # # predictions=model.predict(feats)
    # # print predictions[0]
    # # total=len(labels)
    # # correct=0
    # # for i in range(0, total):
    # #     if labels[i]==predictions[i]:
    # #         correct +=1
    # # print correct, total
    # # print "accuracy: ", float(float(correct)/float(total))
    #
    # NN = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    # NN.fit(giantthing,labels)
    # predictions = NN.predict(giantthing)
    # print NN.score(giantthing, labels)
    # zero=0
    # for i in predictions:
    #     if i == 0:
    #         zero += 1
    # # act=0
    # # for i in labels:
    # #     if i == 0:
    # #         act += 1
    # print "Training data"
    # print "Number of safe urls: ", zero
    # print "Number of malicious urls: ", len(labels)-zero
    # print "percent malicious: ", float(len(labels)-zero)/len(labels)
    # classFeats = None
    # classified = NN.predict(classFeats)
#CLASSIFY.JSON


if __name__ == "__main__":
    main(sys.argv[1:])
