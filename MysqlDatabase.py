import MySQLdb
host = 'localhost'
user = 'root'
password = 'root'
database_name = 'cyberarmrecent'
database_connection = 0
query_cursor = 0

def establish_connection():
    global database_connection
    database_connection = MySQLdb.connect(host=host,user=user,passwd=password,db=database_name)
    global query_cursor
    query_cursor = database_connection.cursor()
    # print database_connection

def insert_asset_database_table():
    file = open('Asset_List','r+')
    asset_list = []
    for line in file:
        line = line.replace('\n','')
        asset_list.append(line)
    print asset_list
    for asset in asset_list:
        cmd_str = 'insert into asset_veris(asset_name) values(%s)'%(asset)
        print cmd_str
        query_cursor.execute('insert into asset_veris(asset_name) values(%s)',(asset))
    database_connection.commit()


def show_tables():
    query_cursor.execute("show tables")
    table_list = query_cursor.fetchall()
    print table_list

def check_connection():
    # execute SQL query using execute() method.
    query_cursor.execute("SELECT VERSION()")

    # Fetch a single row using fetchone() method.
    version = query_cursor.fetchone()
    print "Mysql Version : %s" % (version)

if __name__=='__main__':
    establish_connection()
    print database_connection
    check_connection()
    # show_tables()
    insert_asset_database_table()

