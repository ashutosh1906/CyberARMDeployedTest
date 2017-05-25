import json,os

################################################################################################## Declare Configuration ##########################################################################
FILE_NAME = "Threat_ThreatAction_Asset_Updated_Trial.csv"
DATABASE_PATH = 'VERIS'
ASSET_TAG_NAME = 'asset'
ASSET_TYPE_TAG = 'assets'
SPECIFIC_ASSET_COMMON_KEY = 'variety'
THREAT_NAME = 'action'
THREAT_ACTION_NAME = 'variety'
UNKNOWN_TAG = 'unknown'
AVOID_WORDS = ['notes']
################################################################################################## End of the Configuration #######################################################################
################################################################################################## Global Variables #######################################################################
asset_statistics = {}
################################################################################################## End of Global Variables #######################################################################


def init_custome():
    asset_statistics.clear()

def read_json_threat_report(threat_report,file):
    # print "Name of file : ",file.name

    ###################################################### Asset Type ########################################################################
    asset_list_report = []
    if ASSET_TAG_NAME in threat_report.keys():
        for content in threat_report[ASSET_TAG_NAME].keys():
            if content==ASSET_TYPE_TAG:
                asset_list = threat_report[ASSET_TAG_NAME][content]
                # print "Asset Name : ",
                for specific_asset in asset_list:
                    if SPECIFIC_ASSET_COMMON_KEY in specific_asset.keys():
                        # print "Value %s ",specific_asset[SPECIFIC_ASSET_COMMON_KEY]
                        if '-' in specific_asset[SPECIFIC_ASSET_COMMON_KEY]:
                            asset_exact_name = specific_asset[SPECIFIC_ASSET_COMMON_KEY][(specific_asset[SPECIFIC_ASSET_COMMON_KEY].index('-')+2):]
                        else:
                            asset_exact_name = specific_asset[SPECIFIC_ASSET_COMMON_KEY]#[(specific_asset[SPECIFIC_ASSET_COMMON_KEY].index('-')+2):]
                        asset_list_report.append(asset_exact_name)
                        if asset_exact_name not in asset_statistics.keys():
                            asset_statistics[asset_exact_name] = {}
                        # if asset_exact_name == 'Finance':
                        #     print "Name of the file : ",file.name
                        # print "%s, " %(asset_exact_name),
    # print asset_list_report
    ################################################################# Threat ########################################################################
    if THREAT_NAME in threat_report.keys():
        for threat in threat_report[THREAT_NAME].keys():
            if threat in AVOID_WORDS:
                continue
            if THREAT_ACTION_NAME not in threat_report[THREAT_NAME][threat].keys():
                continue
            ############################################################################## Threat Action ####################################################################
            threat_action_list = threat_report[THREAT_NAME][threat][THREAT_ACTION_NAME]
            # print "%s --> " % (threat),
            for threat_action in threat_action_list:
                # print threat_action,
                if threat_action.lower() == 'disposal error'.lower():
                    print "Check File Name : %s" % (file.name)
                for asset_name in asset_statistics.keys():
                    if threat not in asset_statistics[asset_name].keys():
                        asset_statistics[asset_name][threat] = {}
                    if threat_action not in asset_statistics[asset_name][threat].keys():
                        asset_statistics[asset_name][threat][threat_action] = 0
                    asset_statistics[asset_name][threat][threat_action] += 1
            # print ""

        # for threat in threat_report[THREAT_NAME].keys():
        #     print "%s, " % (threat),
        # print ""

def find_threat_statistics_all():
    init_custome()

    ####################################################### Open the files of the root directory ########################################################
    for root, dir, files in os.walk(DATABASE_PATH, topdown=False):
        for filename in files:
            current_file = open(os.path.join(root, filename), 'r+')
            try:
                threat_report = json.load(current_file)
                read_json_threat_report(threat_report,current_file)
            except:
                print "Here the culprit ",filename
                continue

    ################################################################## Statistics #######################################################################
    # print asset_statistics
    # asset_file = open('SupportedAsset.csv','w')
    # threat_threat_action_file = open(FILE_NAME,'w')
    for asset_name in asset_statistics.keys():
        # asset_file.write("%s\n"%(asset_name))
        for threat in asset_statistics[asset_name].keys():
            for threat_action in asset_statistics[asset_name][threat].keys():
                print "(%s,%s,%s) : %s" % (asset_name,threat,threat_action,asset_statistics[asset_name][threat][threat_action])
                # threat_threat_action_file.write("%s,%s,%s\n" % (asset_name,threat,threat_action))
    # asset_file.close()
    # threat_threat_action_file.close()

if __name__=="__main__":
    find_threat_statistics_all()
