import base64
class CaesarUtils:
    @staticmethod
    def convert_thumbnail_and_cleanup(result):
        print(result["thumbnail"])
        del result["quotahash"],result["quoterkey"]
        result["thumbnail"] = base64.b64encode(result["thumbnail"]).decode()
        