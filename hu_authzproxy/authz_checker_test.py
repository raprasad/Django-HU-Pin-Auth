from authz_checker import AuthZChecker

# FAS_FCOR_MCB_GMF_SVC_AUTHZ_DEV
TEST_AZP_MSG = """http://140.247.108.24/gmf/hu-azp/callback?_azp_token=-----BEGIN+PGP+MESSAGE-----%0D%0AVersion%3A+Cryptix+OpenPGP+0.20050418%0D%0A%0D%0AhQEMA%2FVD%2FGQNXDZ2AQf%2BMn8via%2Bw1DjFTA7nmYWXROYLx37zegaWomS0B%2Be9jL4z%0D%0A7yFLbIXE%2BZ8ujrnblbU2eftx3v7D9UfXBsv93ran%2FvEuqaRY%2FwcmBiMK5iVcDYtl%0D%0ASmmkt6I2TmGfyRUf%2BxFLfxTlGmZ8SqWncrCFZbxRRDf9RjyvspIGbi4kIar837Rq%0D%0AyRQXzbRK3nb0oIXSbYl9g4da1W3a%2B5nqGp3nV5iVcBjlcrTR%2B5IVcfJkHj3Bqh0%2B%0D%0AgNSeGB8WkGsDCZpVGMIQYPP89KG5Bxz%2FqkJckgBv4gGy4sUAh1CFsaKablLvji%2FT%0D%0ADsh9Jbpv8CTBA10NF72KSde8pCFXE%2FhrvGFNnFYWfKUBNJv9tpqXmzzIPWFRe57b%0D%0AG2U6p883U8w3Mx2cx%2B%2F1MzvvTyfD%2FQrFh0lTW1mhnTHdzPp6fHaCcigNhWtekc2g%0D%0AzTGxK1EYzWpZdbG6iBnzlbL9w6%2FCLYtYnRnOSIL9x6AgV8i5oG9IXQip%2FCUwcRwR%0D%0AQ9I3Ml4UJX1gNFE9AFKkDn51ropKHeZjs8j2iamWeeIkIFWWW30mW4zIE9z6nw1V%0D%0ATDx4EnyQkS7bmeq0XFF4%2BfuLibhltTDmbh4JX%2BmP6oFFpQvzU52PP2jrVCkjylS1%0D%0AYSupYroFBJeQAoMT19INAM7UB9QCZHxmOR0s1rpcA3fxwXI747ljkdT9UAbz2oJm%0D%0A7f5%2BcJp%2BjeyEhTCSzxRILUDpnpTpAbsWrxFtZnsK3FmGp%2FlkBEc0B6x7gfWtrITF%0D%0A6gPxvzTt%0D%0A%3DucT9%0D%0A-----END+PGP+MESSAGE-----%0D%0A"""

# FAS_FCOR_MCB_GMF_SVC_AUTHZ
TEST_AZP_MSG2 = """https://adminapps.mcb.harvard.edu/gmf/hu-azp/callback?_azp_token=-----BEGIN+PGP+MESSAGE-----%0D%0AVersion%3A+Cryptix+OpenPGP+0.20050418%0D%0A%0D%0AhQEMA%2FVD%2FGQNXDZ2AQf%2FQBFnFF3pxpws5jF7sSssNIha6x28UOFZXjHG3T4qC8eG%0D%0AZCO3BPxOI3zYflJYj2HQjHTTqFKYRZ3gQsDVHRrL5MAR1DcUy6BlHWsWboT0J2MS%0D%0AlXhK924c3lTTwiTV0H4FsxoDgShO%2Fj09Q83gw2noo%2BmCRA1UUFjSnOcs4q2NeTxn%0D%0Awpyswz5cVtg3Ppa%2BPOE4t%2F9ydvuWU%2Bc5TnaFZaSSX7RR11%2BdPlGZ4a8XwL%2Fga2Qb%0D%0AoDLRIeAaQIFEfR8%2B%2BVaFS7LdrhJseIYQm06l1%2F7Hg3odvGa2AUo%2Fru6tREOCbNms%0D%0A5P1foAB8mKphvlbIY6T%2FTsI5pcrbICx%2B%2FYC2U%2F4WyqUBLObOnCdIbFDFO2QRqpAa%0D%0AiPxZd9nV1VDUcu16%2FqV03qODH9V9bGEvWSAeWw9qSueZvHJJxnu%2FviPg5KKckHm4%0D%0AtzsYtAgDQMcOo4QhHgg8wzXCqfcKAnoF16IrnAsj3CBvHEZa0f%2B5UniVdIKJIj%2Fi%0D%0Az6XuavLHzV3YXaCHVrUAkOB9qukzS5Qa0%2FDmLX3%2BkcGaf7z71oyPEM9RQ%2BhOGmdM%0D%0A40gqepz6O%2B52gncQGSrAtAcgqYxZJcYxfryMgVHodRNKc0MvOrtCWeejZ9tM%2FThg%0D%0A46wu%2BOCG%2FA2X0PjsTWg7DVs5z9lFuq0RuEjbaOG%2BmLl5sO7%2FhLFg3A3oReOsmWww%0D%0AwP2SO1CgvXrRsiozkEdGruhnFno8tJh9HRSY1MD7NIuUmN0Bm45Iudp9BcDIvA%3D%3D%0D%0A%3DHzvN%0D%0A-----END+PGP+MESSAGE-----%0D%0A"""

# FAS_FCOR_MCB_GMF_SVC_AUTHZ
TEST_AZP_MSG3 = """http://140.247.108.24/course-tracker/hu-azp/callback/?_azp_token=-----BEGIN+PGP+MESSAGE-----%0D%0AVersion%3A+Cryptix+OpenPGP+0.20050418%0D%0A%0D%0AhQEMA%2FVD%2FGQNXDZ2AQgAmWDUrHDm1cUR5ZIP053yxHcOa%2Ftx4ff7forRU%2FMyjEMw%0D%0ApkqSJAbWSrrX%2FhcymbbFxgATIvx30K7iz44JURHlqzD2gGP40coqC%2FDgXZx8Pq3Y%0D%0AI7UbLmeOcWoqerqmZqIuCP%2BkqDGbBP%2Bz498%2BVN3lJ2dagcwng1WtfWkxIlLpy3Ed%0D%0ATEzPNJnIqi4WEKifbprqUb9qPm3fx%2FvxogLCGNjX5ir8IYiHrnxGud9H7En2Wiiq%0D%0AtD0CtwiE3gqQ4%2Fayzb1lS2ziQ%2FHSZ%2BtT0shAcaGZrJhZ6jx7vxXj3cS1XYW9VpCe%0D%0A7RiStdBZXeaLiOQlq3gfT9QKB29JbsKW4rT34EdO2KUBNfa4Ir3wbyduo7gp2N5M%0D%0An%2FP%2BWeUA%2FwEAZLvmZJ43MT0B08Bm40Cg%2BrsihnSgGFvint6lqm2qJ7b1448BWO4h%0D%0ABbtQ5lFUu1qwZPffDZJLwzqqtOOP67zgVFvIYL8Ez3C4fBODPdXA7DWggc6PQ0mN%0D%0A8s%2FPnSkl0FjFEh%2BSklcde%2Fh1GBwWwnOyJyug36H%2Bp80GbKfCjHXW%2FupMuMoyTgvr%0D%0AGV%2BxN08Nh5nfh7Sfaq%2FtPU4A5qfBjqkUHs6gQYu1FijI%2BFSprI6RU%2FLTIk%2FgDXHC%0D%0A2cCSIojSlgJB%2Bo4rKl%2FCmoNkpT1cK3%2BNzM47nas0Qyp%2FbWC0JMcUfPd%2B106qfBXB%0D%0AmaSWi4kePCKkWna9mBIdfZc3yd8g%2FD6c25Ywbe1Hoi7j10Kuf3GYDTwuzElVC2BD%0D%0AT%2FM9UmEr2g%3D%3D%0D%0A%3Dy0Wv%0D%0A-----END+PGP+MESSAGE-----%0D%0A"""

if __name__ == '__main__':
    """
    Run test
    """
    from authz_proxy_validation_info import AuthZProxyValidationInfo

    authz_validation_info = AuthZProxyValidationInfo(request=None\
                                ,app_names=['FAS_FCOR_MCB_GMF_SVC_AUTHZ', 'FAS_FCOR_MCB_COURSEDB_AUTHZ_DEV']\
                                , gnupghome='gpg-test'
                                , gpg_passphrase='gpgmove'
                                , is_debug=True)

    authz_validation_info.set_url_fullpath_manually(TEST_AZP_MSG3)                             
    authz_validation_info.set_client_ip_manually('140.247.108.24')

    zcheck = AuthZChecker(authz_validation_info)

    zcheck.show_errs()
    zcheck.show_user_vals()
