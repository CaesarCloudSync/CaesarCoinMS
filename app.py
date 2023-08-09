from flask import Flask,request
from caesarcrud import CaesarCRUD
import datetime as dt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from caesarhash import CaesarHash
from flask_cors import CORS, cross_origin
from caesar_create_tables import CaesarCreateTables
import base64
from flask_socketio import SocketIO,emit
import jwt
import json
from flask_jwt_extended.utils import decode_token
import time
#https://medium.com/@adrianhuber17/how-to-build-a-simple-real-time-application-using-flask-react-and-socket-io-7ec2ce2da977
app = Flask(__name__)
jwt = JWTManager(app)
app.config['SECRET_KEY'] = 'secret!'
CORS(app,resources={r"/*":{"origins":"*"}})
socketio = SocketIO(app,cors_allowed_origins="*")
JWT_SECRET = "Peter Piper picked a peck of pickled peppers, A peck of pickled peppers Peter Piper picked, If Peter Piper picked a peck of pickled peppers,Where's the peck of pickled peppers Peter Piper picked" #'super-secret'
JWT_ALGORITHM = app.config["JWT_ALGORITHM"]
app.config['JWT_SECRET_KEY'] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = dt.timedelta(days=1)

caesarcrud = CaesarCRUD()

# quotaposters table
caesarcreatetables = CaesarCreateTables()
caesarcreatetables.create(caesarcrud)
def jwt_secure_decode(authjwtheaderjson:dict):
    authorization = authjwtheaderjson["headers"]["Authorization"].replace("Bearer ","")
    current_user = decode_token(authorization)["sub"]
    return current_user
# $C, R, U, D

@app.route('/quotapostersignup',methods=['POST'])
@cross_origin()
def quotapostersignup():
    try:
        signininfo = request.get_json()
        table = "quotaposters"
        company = signininfo['company']
        email = signininfo['email']
        password = signininfo['password']
        companyidentity = CaesarHash.hash_text(company + ":" + email)
        #print(companyidentity)
        fields = caesarcreatetables.quotapostersfields
        condition = f"company = '{company}' AND email = '{email}'"
        #print(condition)
        company_exists = caesarcrud.check_exists(("*"),table,condition)
        #print(company_exists)
        if company_exists:
            return {"message":"company already exists"}
        else:
            passwordhash = CaesarHash.hash_text_auth(password)
            result = caesarcrud.post_data(fields,(company,email,passwordhash),table)
            if result:
                access_token = create_access_token(identity=companyidentity)
                return {"access_token":access_token}
            else:
                return {"error":result["error"]}
    except Exception as ex:
        return {"error":f"{type(ex)}-{ex}"}
@app.route('/quotapostersignin',methods=['POST'])
@cross_origin() 
def quotapostersignin():
    try:
        signininfo = request.get_json()
        table = "quotaposters"
        company = signininfo['company']
        email = signininfo['email']
        password = signininfo['password']
        companyidentity = CaesarHash.hash_text(company + ":" + email)
        fields = caesarcreatetables.quotapostersfields
        condition = f"company = '{company}' AND email = '{email}'"
        company_exists = caesarcrud.check_exists(("*"),table,condition)
        if company_exists:
            result = caesarcrud.get_data(fields,table,condition)[0]
            password_matches = CaesarHash.match_hashed_text(result['password'],password)
            if password_matches:
                access_token = create_access_token(identity=companyidentity)
                return {"access_token":access_token}
            else:
                return {"message":"incorrect username or password"}
        else:
            return{"message":"incorrect username or password"}

    except Exception as ex:
        return {"error":f"{type(ex)}-{ex}"}
@app.route('/contributorsignin',methods=['POST'])
@cross_origin() 
def contributorsignin():
    try:
        signininfo = request.get_json()
        table = "contributors"
        email = signininfo['email']
        password = signininfo['password']
        contributoridentity = CaesarHash.hash_text(email)
        fields = caesarcreatetables.contributorsfields
        condition = f"email = '{email}'"
        contributor_exists = caesarcrud.check_exists(("*"),table,condition)
        if contributor_exists:
            result = caesarcrud.get_data(fields,table,condition)[0]
            password_matches = CaesarHash.match_hashed_text(result['password'],password)
            if password_matches:
                access_token = create_access_token(identity=contributoridentity)
                return {"access_token":access_token}
            else:
                return {"message":"incorrect username or password"}
        else:
            return{"message":"incorrect username or password"}

    except Exception as ex:
        return {"error":f"{type(ex)}-{ex}"}
@app.route('/contributorsignup',methods=['POST'])
@cross_origin()
def contributorsignup():
    try:
        signininfo = request.get_json()
        table = "contributors"
        email = signininfo['email']
        password = signininfo['password']
        companyidentity = CaesarHash.hash_text(email)
        fields = caesarcreatetables.contributorsfields
        condition = f"email = '{email}'"
        contributor_exists = caesarcrud.check_exists(("*"),table,condition)
        if contributor_exists:
            return {"message":"contributor already exists"}
        else:
            passwordhash = CaesarHash.hash_text_auth(password)
            result = caesarcrud.post_data(fields,(email,passwordhash),table)
            if result:
                access_token = create_access_token(identity=companyidentity)
                return {"access_token":access_token}
            else:
                return {"error":result["error"]}
    except Exception as ex:
        return {"error":f"{type(ex)}-{ex}"}
 

@app.route("/postquota",methods=["POST"])
@cross_origin()
@jwt_required() 
def postquota():
    user = get_jwt_identity()
   
    if user:
        try:
            data = request.get_json()
            table = "quotas"
            fields = caesarcreatetables.quotasfields
            quotatype = data["quotatype"]
            #print(data)

            quotahash = CaesarHash.hash_quota(data)
            quota_exists = caesarcrud.check_exists(("*"),table,f"quotahash = '{quotahash}'")
            if not quota_exists:
                data["quotahash"] = quotahash
                data["quoterkey"] = user
                thumbnail = data["thumbnail"] 
                
                filetype,thumbnailimg = thumbnail.split(",", 1)[0] + ",",thumbnail.split(",", 1)[1]
                thumbnailimg = thumbnailimg.encode("utf-8")
                thumbnailimg = base64.decodebytes(thumbnailimg)
                data["thumbnail"] = thumbnailimg
                data["thumbnailfiletype"] = filetype
                #print("ho")

                if tuple(data.keys()) == fields:
                
                    keys,data = caesarcrud.json_to_tuple(data)
                    #print(fields)
                    result = caesarcrud.post_data(fields,data,table)
                    if result:
                        quotatypetable = "quotatypes"
                        quotatypfields = caesarcreatetables.quotatypes
                        quotatypecondition = f"quotatype = '{quotatype}'"
                        quotatype_exists = caesarcrud.check_exists(("*"),quotatypetable,quotatypecondition)

                        if not quotatype_exists:
                            quotatyperesult = caesarcrud.post_data(quotatypfields,tuple([quotatype]),quotatypetable)
                            if quotatyperesult:
                                return {"message":"quota was posted."}
                            else:
                                return {"error":"quotatype was not added."}
                        else:
                            return {"message":"quota was posted."}
                    else:
                        return {"error":"An error occured, the quota was not posted."}

   
                else:
                    return {"error":"server side error, fields and values don't align."}

                
                #return {"message":"quota has been posted."}
            else:
                return {"message":"quota already exists."}
        except Exception as ex:
            return {"error":f"{type(ex)} -{ex}"}
    else:
        return {"error":"send jwt header."}
@app.route("/updatequota",methods=["PUT"])
@cross_origin()
@jwt_required() 
def updatequota():
    user = get_jwt_identity()
   
    if user:
        try:
            data = request.get_json()
            table = "quotas"
            old_quota = data["previousquota"]
            del data["previousquota"]
            quota = data
            old_quotahash = CaesarHash.hash_quota(old_quota)
            conditioncheck = f"quoterkey = '{user}' AND quotahash = '{old_quotahash}'"
            print(conditioncheck)
            quota_exists = caesarcrud.check_exists(("*"),table,conditioncheck)
            if "quotatitle" in quota and "quotatype" in quota:
                newquotahash = CaesarHash.hash_quota(quota)
            elif "quotatitle" in quota and "quotatype" not in quota:
                quotahashinp = {"quotatitle":quota["quotatitle"],"quotatype":old_quota["quotatype"]}
                newquotahash = CaesarHash.hash_quota(quotahashinp)
            elif "quotatitle" not in quota and "quotatype" in quota:
                quotahashinp = {"quotatitle":old_quota["quotatitle"],"quotatype":quota["quotatype"]}
                newquotahash = CaesarHash.hash_quota(quotahashinp)
            elif "quotatitle" not in quota and "quotatype" not in quota:
                newquotahash = None

            if quota_exists:
                
                if "thumbnail" in quota:
                    thumbnail = quota["thumbnail"]
                    filetype,thumbnailimg = thumbnail.split(",", 1)[0] + ",",thumbnail.split(",", 1)[1]
                    thumbnailimg = thumbnailimg.encode("utf-8")
                    thumbnailimg = base64.decodebytes(thumbnailimg)
                    fieldthumbnail,thumbnailvalue = "thumbnail",thumbnailimg
                    fieldthumbnailtype,thumbnailtypevalue = tuple(["thumbnailfiletype"]),tuple([filetype])
                    result = caesarcrud.update_blob(fieldthumbnail,thumbnailvalue,table,conditioncheck)
                    result = caesarcrud.update_data(fieldthumbnailtype,thumbnailtypevalue,table,conditioncheck)
                    del quota["thumbnail"]

                

                fieldsupdate = tuple(quota.keys())
                valuesupdate = tuple(quota.values())
                result = caesarcrud.update_data(fieldsupdate,valuesupdate,table,conditioncheck)
                if newquotahash:
                    fieldquotahash,quotahashvalue = tuple(["quotahash"]),tuple([newquotahash])
                    result = caesarcrud.update_data(fieldquotahash,quotahashvalue,table,conditioncheck)


                if result:
                    return {"message":"quota was updated."}
                else:
                    return {"message":"quota was not updated."}
            else:
                return {"message":"quota doesn't exist."}
            # check old quota exixts
            # update set field  = newquota , condition oldquotahash
             
        except Exception as ex:
            return {"error":f"{type(ex)} -{ex}"}
@app.route("/responsequota",methods=["POST"])
@cross_origin()
def responsequota():
    data = request.get_json()
    return data

@socketio.on("getquotasbrowsews")
def getquotasbrowsews(dummydata):
    
    try:
        table = "quotas"
        fields = caesarcreatetables.quotasfields
        condition = f"visibility = 'public'"
        public_quota_exists = caesarcrud.check_exists(("*"),table,condition)
        #print(quoter_exists,"ho")
        if public_quota_exists:
            resultone = caesarcrud.get_data(fields,table,condition,getamount=1)
            if resultone:
                results = caesarcrud.get_large_data(fields,table,condition)
                for result in results:
                    
                    result = caesarcrud.tuple_to_json(fields,result)
                    del result["quotahash"],result["quoterkey"]
                    result["thumbnail"] = base64.b64encode(result["thumbnail"]).decode()
                    #print(result,"hi")
                    emit("getquotasbrowsews",{'data':result,'id':request.sid},broadcast=True)
                emit("getquotasbrowsews",{'data':{"message":"all data has been sent."},'id':request.sid},broadcast=True)
                    
            else:
                emit("getquotasbrowsews",{'data':{"message":"quotas do not exist."},'id':request.sid},broadcast=True)
        else:
            emit("getquotasbrowsews",{'data':{"message":"quoter has not posted first quota yet."},'id':request.sid},broadcast=True)


    except Exception as ex:
        emit("getquotasws",{"error":f"{type(ex)} - {ex}"},broadcast=True)

@socketio.on("getquotasws")
def getquotasws(authinfo):
    
    try:
        #print(type(authinfo),authinfo)
        #authinfojson = json.loads(authinfo)
        current_user = jwt_secure_decode(authinfo)
        #print(current_user)
    

        table = "quotas"
        fields = caesarcreatetables.quotasfields
        condition = f"quoterkey = '{current_user}'"
        #print(condition)
        quoter_exists = caesarcrud.check_exists(("*"),table,condition)
        #print(quoter_exists,"ho")
        if quoter_exists:
            resultone = caesarcrud.get_data(fields,table,condition,getamount=1)
            if resultone:
                results = caesarcrud.get_large_data(fields,table,condition)
                for result in results:
                    
                    result = caesarcrud.tuple_to_json(fields,result)
                    del result["quotahash"],result["quoterkey"]
                    result["thumbnail"] = base64.b64encode(result["thumbnail"]).decode()
                    #print(result,"hi")
                    emit("getquotasws",{'data':result,'id':request.sid},broadcast=True)
                emit("getquotasws",{'data':{"message":"all data has been sent."},'id':request.sid},broadcast=True)
                    
            else:
                emit("getquotasws",{'data':{"message":"quotas do not exist."},'id':request.sid},broadcast=True)
        else:
            emit("getquotasws",{'data':{"message":"quoter has not posted first quota yet."},'id':request.sid},broadcast=True)


    except Exception as ex:
        if "(2013, 'Lost connection to MySQL server during query')" in str(ex):
            print("DB reset.")
            caesarcrud.caesarsql.reset_connection()
        emit("getquotasws",{"error":f"{type(ex)} - {ex}"},broadcast=True)

@app.route("/getquota/<path:subpath>",methods=["GET"])
def getquota(subpath):
    try:
        table = "quotas"
        url = subpath.split("/")
        fields = caesarcreatetables.quotasfields
        data = {"quotatitle":url[1],"quotatype":url[2]}
        quotahash = CaesarHash.hash_quota(data)
        condition = f"quotahash = '{quotahash}' AND visibility = 'public'"
        
        quota_exists = caesarcrud.check_exists(("*"),table,condition)
        if quota_exists:
            quota = caesarcrud.get_data(fields,table,condition)[0]
            
            del quota["quotahash"],quota["quoterkey"]
            quota["thumbnail"] = base64.b64encode(quota["thumbnail"]).decode()
            return quota
        else:
            return {"quota doesn't exist."}

        

    except Exception as ex:
        return {"error":f"{type(ex)} -{ex}"}
@app.route("/deletequota/<path:subpath>",methods=["DELETE"])
@jwt_required()
def deletequota(subpath):
    user = get_jwt_identity()
    if user:
        try:
            table = "quotas"
            url = subpath.split("/")
            data = {"quotatitle":url[1],"quotatype":url[2]}
            quotahash = CaesarHash.hash_quota(data)
            condition = f"quotahash = '{quotahash}' AND quoterkey = '{user}'"
            quota_exists = caesarcrud.check_exists(("*"),table,condition)
            if quota_exists:
                quota = caesarcrud.delete_data(table,condition)
                if quota:
                    return {"message":"quota was deleted."}
                else:
                    return {"message":"quota was not deleted."}
            else:
                return {"message":"quota doesn't exist."}

            

        except Exception as ex:
            return {"error":f"{type(ex)} -{ex}"}
@app.route("/getquotatypes",methods=["GET"])
def getquotatypes():
    try:
        fields = caesarcreatetables.quotatypes
        table = "quotatypes"
        quotatype_exists = caesarcrud.check_exists(("*"),table)
        if quotatype_exists:
            quotas = caesarcrud.get_data(fields,table,getamount=12)
            #rint(quotas)
            return {"quotatypes":quotas}
        else:
            return {"error":"there are no quotatypes."}
        



    except Exception as ex:
        return {"error":f"{type(ex)} -{ex}"}



@socketio.on('data')
def handle_message(data):
    """event listener when client types a message"""
    print("data from the front end: ",str(data))
    emit("data",{'data':data,'id':request.sid},broadcast=True)





@app.route('/')
def hello_geek():
    print("hi")
    return '<h1>Welcome to the CaesarCoinMicroServices</h1>'
# generate jwt, and time -> hash 
# make request to 

# TODO Create quota poster CRUD API's

if __name__ == "__main__":
    socketio.run(app, debug=True,port=8080,host="0.0.0.0")#,port=5000)
    #app.run(host="0.0.0.0", port=5000,debug=True)