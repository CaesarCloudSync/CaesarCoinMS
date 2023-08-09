from flask import Flask,request
from caesarcrud import CaesarCRUD
import datetime as dt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from caesarhash import CaesarHash
from flask_cors import CORS, cross_origin
from caesar_create_tables import CaesarCreateTables
import base64
from flask_sock import Sock
import jwt
import json
from flask_jwt_extended.utils import decode_token
import time
app = Flask(__name__)
jwt = JWTManager(app)
sock = Sock(app)
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
        print(companyidentity)
        fields = caesarcreatetables.quotapostersfields
        condition = f"company = '{company}' AND email = '{email}'"
        company_exists = caesarcrud.check_exists(("*"),table,condition)
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

            quotahash = CaesarHash.hash_quota(user,data)
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

                if tuple(data.keys()) == fields:
                    keys,data = caesarcrud.json_to_tuple(data)
                    result = caesarcrud.post_data(fields,data,table)
                    if result:
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
@app.route("/responsequota",methods=["POST"])
@cross_origin()
def responsequota():
    data = request.get_json()
    return data
@app.route("/getquotas",methods=["POST"])
@cross_origin()
def getquotas():
    try:
        #print(authinfo)
        authinfojson = request.get_json()
        print(authinfojson)
        current_user = jwt_secure_decode(authinfojson)
        #print(current_user)
    

        table = "quotas"
        fields = caesarcreatetables.quotasfields
        condition = f"quoterkey = '{current_user}'"
        print(condition)
        quoter_exists = caesarcrud.check_exists(("*"),table,condition)
        if quoter_exists:
            resultone = caesarcrud.get_data(fields,table,condition,getone=0)
            if resultone:
                results = caesarcrud.get_large_data(fields,table,condition)
                for result in results:
                    
                    result = caesarcrud.tuple_to_json(fields,result)
                    del result["quotahash"],result["quoterkey"]
                    result["thumbnail"] = base64.b64encode(result['thumbnail']).decode()
                    
                    

                    yield result
            else:
                return {"message":"quotas do not exist."}
        else:
            return {"message":"quoter has not posted first quota yet."}


    except Exception as ex:
        return {"error":f"{type(ex)} - {ex}"}

@sock.route('/echo')
@cross_origin()
def echo(sock):
    while True:
        data = sock.receive()
        sock.send(data)
@sock.route("/getquotasws")
@cross_origin()
def getquotasws(sock):
    while True:
        authinfo = sock.receive()
        try:
            #print(authinfo)
            authinfojson = json.loads(authinfo)
            current_user = jwt_secure_decode(authinfojson)
            print(current_user)
        

            table = "quotas"
            fields = caesarcreatetables.quotasfields
            condition = f"quoterkey = '{current_user}'"
            print(condition)
            quoter_exists = caesarcrud.check_exists(("*"),table,condition)
            if quoter_exists:
                resultone = caesarcrud.get_data(fields,table,condition,getone=0)
                if resultone:
                    results = caesarcrud.get_large_data(fields,table,condition)
                    for result in results:
                     
                        result = caesarcrud.tuple_to_json(fields,result)
                        del result["quotahash"],result["quoterkey"]
                        sock.send(result)
                else:
                    sock.send({"message":"quotas do not exist."})
            else:
                sock.send({"message":"quoter has not posted first quota yet."})


        except Exception as ex:
            sock.send({"error":f"{type(ex)} - {ex}"})




@app.route('/')
def hello_geek():
    return '<h1>Welcome to the CaesarCoinMicroServices</h1>'
# generate jwt, and time -> hash 
# make request to 

# TODO Create quota poster CRUD API's

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)