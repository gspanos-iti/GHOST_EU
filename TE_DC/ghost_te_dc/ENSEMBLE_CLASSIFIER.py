from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn import tree
import numpy as np


class EC:

    #TRAINING OF CLASSIFIERS
    def ensemble_training(self,x, y):
        #Random Forest
        randforest = RandomForestClassifier()
        #Support Vector Machine
        svm = SVC(probability=True)
        #Gaussian Naive Bayes
        gnb = GaussianNB()
        #Decision Tree
        dtree = tree.DecisionTreeClassifier()              
        #set the random seed equal to 0
        np.random.seed(0)
        eclf1 = VotingClassifier(estimators=[('randforest', randforest), ('svm', svm), ('gnb', gnb), ('dtree', dtree)], voting='soft')
        eclf1 = eclf1.fit(x, y)
        return(eclf1)
