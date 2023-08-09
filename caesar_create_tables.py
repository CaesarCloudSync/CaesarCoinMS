class CaesarCreateTables:
    def __init__(self) -> None:
        self.quotapostersfields = ("company","email","password")
        self.contributorsfields = ("email","password")
        self.quotasfields = ("quoter","quotatitle","quotatype","thumbnailfilename","thumbnail","description","visibility","quotahash","quoterkey","thumbnailfiletype")
        self.numquotas = ("quoterkey","numofquotas")
        self.quotatypes = ("quotatype",)
    def create(self,caesarcrud):
        caesarcrud.create_table("quotaposterid",self.quotapostersfields,
        ("varchar(255) NOT NULL","varchar(255) NOT NULL","varchar(255) NOT NULL"),
        "quotaposters")
        caesarcrud.create_table("contributorid",
        self.contributorsfields,
        ("varchar(255) NOT NULL","varchar(255) NOT NULL"),
        "contributors")
        caesarcrud.create_table("quotaid",
        self.quotasfields,
        ("varchar(255) NOT NULL","varchar(255) NOT NULL","varchar(255) NOT NULL","varchar(255) NOT NULL",
         "mediumblob NOT NULL","varchar(255) NOT NULL","varchar(255) NOT NULL","varchar(255) NOT NULL",
         "varchar(255) NOT NULL","varchar(255) NOT NULL"),
        "quotas")
        caesarcrud.create_table("quotatypeid",
        self.quotatypes,
        ("varchar(255) NOT NULL",),
        "quotatypes")