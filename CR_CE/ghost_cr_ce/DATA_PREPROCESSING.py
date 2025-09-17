#import the required libraries
import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

class DP:
    def data_preprocessing(self, features):
        #standardization of the data before the PCA
        scaler = StandardScaler()
        scaler.fit(features)
        features=scaler.transform(features)

        ##REDUCTION OF DATA DIMENSION WITH PCA
        ##first preliminary run of PCA
        pca = PCA()
        pca.fit(features)
        #find the optimal number of components depending on the average eigenvalue (Guttman-Kaiser criterion - Jolliffe modification)
        number_of_components=0
        #print (pca.explained_variance_)
        while number_of_components < len(pca.explained_variance_):
            if np.asanyarray(pca.explained_variance_)[number_of_components] >= 0.7:
                number_of_components += 1
            else:
                break

        #run of PCA with the optimal number of components
        pca = PCA(n_components = number_of_components, whiten = True)
        #fit PCA to the features
        pca.fit(features)
       
        #transform and reduce dimension of data
        red_data = pca.transform(features)
        #return reduction data, scaling and principal components parameters
        return(red_data, scaler, pca)