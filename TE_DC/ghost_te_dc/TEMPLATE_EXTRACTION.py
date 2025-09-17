import pickle
from psycopg2.extras import Json
import numpy as np
from sklearn.decomposition import PCA
from collections import Counter
from DATABASE_COMMUNICATION import DBC
from scipy.spatial import distance


class TEMPLATE_EXTRACTION:

    def __init__(self, config):
        self.name = config.get("Database", "name")
        self.user = config.get("Database", "user")
        self.password = config.get("Database", "password")
        self.host = config.get("Database", "host")
        self.port = config.get("Database", "port")

    def TE(self, clusters, red_data, duration):
        a=Counter(clusters).keys()
        b=Counter(clusters).values()        
        num_of_clusters = len(a)

        #connect to db with
        ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
        pca_name = "pca_" + duration
        ps_cur.execute("SELECT * from cr_ce_parameters WHERE name = %s;", (pca_name,))
        query = ps_cur.fetchall()    
        DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
        pca = pickle.loads(query[0][1])       

        
        #REDUCTION DATA CLUSTERING
        templates = np.zeros((num_of_clusters, pca.n_components))

        for i in range(len(clusters)):
            for j in range(num_of_clusters):
                if  clusters[i] == a[j]:
                    break
            for k in range(pca.n_components):
                templates[j][k] = templates[j][k] + red_data[i][k]    


        table_templates = {}
        ps_cur, conn = DBC(self.name, self.user, self.password, self.host, self.port).connect()
        #Computation of the templates
        for j in range(num_of_clusters):
            devices_reg = []
            for k in range(pca.n_components):
                templates[j][k] = templates[j][k]/b[j]
                table_templates["PCA" + str(k)] = templates[j][k]
            for i, cl in enumerate(clusters):
                if cl == a[j]:
                    devices_reg.append(i)

            ps_cur.execute("INSERT INTO templates (template) VALUES ({});".format(Json(table_templates)))            

        DBC(self.name, self.user, self.password, self.host, self.port).disconnect(conn)
        return(templates)

    def DST_CL(self, clusters, templates, training_data):
        b = Counter(clusters).values() 
        distances =[[] for i in range(len(templates))] 
        for td in training_data:
            for i, dev_dt in enumerate(td):
                distances[clusters[i]].append(distance.minkowski(dev_dt, templates[clusters[i]], p = 2))
        for i, dst in enumerate(distances):
            distances[i] = np.mean(distances[i]) + 2 * np.std(distances[i])
        return(distances)


