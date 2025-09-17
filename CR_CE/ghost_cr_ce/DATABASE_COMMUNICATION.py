import psycopg2

class DBC:
    #iniitalization
    def __init__(self, name, user, password, host, port):
        # Postgresql config details
        self.params={'database': name, 'user': user, 'password': password, 'host': host, 'port': port}
        
    
    #CONNECT TO DATABASE
    def connect(self):
        conn = psycopg2.connect(**self.params)
        ps_cur = conn.cursor()
        return(ps_cur, conn)

    #DISCONNECT FROM THE DATABASE
    def disconnect (self, conn):
        conn.commit()
        conn.close()
