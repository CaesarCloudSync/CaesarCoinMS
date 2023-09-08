    @app.route("/storemagneturi",methods=["GET","POST"])
@cross_origin()
@jwt_required()
def storemagneturi():
	current_user = get_jwt_identity()
	if current_user:
		try:
			torrentdetails = request.get_json()
			# TODO create a block for the blockchain without long mining and just reward them with a larger cut of coin.
			companyid = str(hashlib.sha256(torrentdetails["companyname"].encode()).hexdigest())
			quota_accepted_exists = importcsv.db.quotas_accepted.find_one({"companyid": companyid})
			if quota_accepted_exists:
				quota_company_accepted = importcsv.db.quotas_accepted.find({"companyid": companyid})[0]
				# Get quota hash value
				quota_exists = importcsv.db.quotas.find_one({"companyid": companyid})
				if quota_exists:
					quotahashvalue = ""
					quotas_db= importcsv.db.quotas.find({"companyid": companyid})[0]
					for quota in quotas_db["quotas"]:
						if quota["title"] == torrentdetails["quotaname"]:
							quotahashvalue += quota["quotahashvalue"]
					if len(quotahashvalue) > 0:			
						try:
							if current_user in quota_company_accepted[quotahashvalue]["contributors"]:
								magneturi_exists = importcsv.db.quotamagneturis.find_one({"companyid": companyid})
								#original_contributor_string = str(current_user)+ companyid + torrentdetails["quotaname"] + torrentdetails["torrentfilename"] + torrentdetails["torrentmagneturi"]
								#original_contributor_hash = str(hashlib.sha256(original_contributor_string.encode()).hexdigest())
								if magneturi_exists:

									try:
										magneturi_db = importcsv.db.quotamagneturis.find({"companyid": companyid})[0]
										jsonstore = {"quotaname":torrentdetails["quotaname"],"torrentfilename":torrentdetails["torrentfilename"],"torrentmagneturi":torrentdetails["torrentmagneturi"],"original_contributor_name":torrentdetails["contributorname"],"filesize":torrentdetails["filesize"]} #"original_contributor_hash":original_contributor_hash,
										if jsonstore in magneturi_db["quotas"]:
											return {"message":"magneturi already exists"},200
										elif jsonstore not in magneturi_db["quotas"]:
											magneturi_db["quotas"].append(jsonstore)
											importcsv.db.quotamagneturis.replace_one({"companyid": companyid},magneturi_db)
											return {"message":"magneturi added"},200
									except KeyError as kexe:
										return {"error":f"magneturi exists but: {type(kexe)},{kexe}"},200
								elif not magneturi_exists:
									importcsv.db.quotamagneturis.insert_one({"companyid":companyid,"quotas":[{"quotaname":torrentdetails["quotaname"],"torrentfilename":torrentdetails["torrentfilename"],"torrentmagneturi":torrentdetails["torrentmagneturi"],"original_contributor_name":torrentdetails["contributorname"],"filesize":torrentdetails["filesize"]}]}) #"original_contributor_hash":original_contributor_hash,
									return {"message":"magneturi stored."},200
							elif current_user not in quota_company_accepted[quotahashvalue]["contributors"]:
								return {"error":"contributor is not authorized to send data to this quota."},200
						except KeyError as kex:
							return {"error":f"company or contributor doesn't exist.{type(kex)},{kex}"},200
				elif len(quotahashvalue) == 0:
					return {"error":"quota does not exist."},200
			elif not quota_accepted_exists:
				return {"error":"company acceptance collection does not exist."},200
		except Exception as ex:
			return {"error":f"{type(ex)},{ex}"},400
